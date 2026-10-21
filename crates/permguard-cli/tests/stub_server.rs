// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The CLI against a server-shaped stub: a real socket, canned answers.
//!
//! What lives here is everything the offline suite cannot reach — the HTTP
//! client, the catalog commands, discovery verification, `inspect` — without
//! depending on the real server crates. The stub speaks just enough
//! HTTP/1.1 to satisfy the client, from a routing table each test declares.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::collections::HashMap;
use std::io::{BufRead as _, BufReader, Read as _, Write as _};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::Arc;

/// A canned HTTP/1.1 answerer: method+path → (status, body), the query left out of the match.
/// Unknown paths answer 404 with the structured refusal shape. Every request is kept, as
/// `METHOD target body`, for a test that asserts what the CLI sent.
struct Stub {
    address: String,
    requests: Arc<std::sync::Mutex<Vec<String>>>,
    _server: std::thread::JoinHandle<()>,
}

fn serve(routes: HashMap<(&'static str, &'static str), (u16, String)>) -> Stub {
    let routes: HashMap<(String, String), (u16, String)> = routes
        .into_iter()
        .map(|((method, path), answer)| ((method.to_owned(), path.to_owned()), answer))
        .collect();
    serve_owned(routes)
}

fn serve_owned(routes: HashMap<(String, String), (u16, String)>) -> Stub {
    let listener = TcpListener::bind("127.0.0.1:0").expect("a port is free");
    let address = format!("127.0.0.1:{}", listener.local_addr().unwrap().port());
    let routes = Arc::new(routes);
    let requests = Arc::new(std::sync::Mutex::new(Vec::new()));
    let kept = Arc::clone(&requests);

    let server = std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { break };
            let routes = Arc::clone(&routes);
            let kept = Arc::clone(&kept);
            std::thread::spawn(move || {
                // One exchange per connection: the client sends
                // `Connection: close` and reads to EOF, so the stub answers
                // once and hangs up.
                {
                    let mut reader = BufReader::new(stream.try_clone().expect("clones"));
                    let mut request_line = String::new();
                    if reader.read_line(&mut request_line).unwrap_or(0) == 0 {
                        return;
                    }
                    let mut parts = request_line.split_whitespace();
                    let method = parts.next().unwrap_or("").to_owned();
                    let path = parts.next().unwrap_or("").to_owned();

                    // Drain headers; honour a body via content-length.
                    let mut length = 0usize;
                    loop {
                        let mut header = String::new();
                        if reader.read_line(&mut header).unwrap_or(0) == 0 {
                            return;
                        }
                        let header = header.trim();
                        if header.is_empty() {
                            break;
                        }
                        if let Some(value) = header
                            .to_ascii_lowercase()
                            .strip_prefix("content-length:")
                            .map(str::trim)
                            .and_then(|v| v.parse().ok())
                        {
                            length = value;
                        }
                    }
                    let mut body = vec![0u8; length];
                    if length > 0 {
                        reader.read_exact(&mut body).expect("the body reads");
                    }

                    kept.lock().expect("the log").push(format!(
                        "{method} {path} {}",
                        String::from_utf8_lossy(&body)
                    ));
                    let route = path.split('?').next().unwrap_or_default().to_owned();
                    let (status, answer) = routes
                        .get(&(method.clone(), route))
                        .cloned()
                        .unwrap_or((
                        404,
                        r#"{"class":"not_found","code":"not_found","message":"nothing answers"}"#
                            .to_owned(),
                    ));
                    let response = format!(
                        "HTTP/1.1 {status} X\r\ncontent-type: application/json\r\n\
                         content-length: {}\r\nconnection: close\r\n\r\n{answer}",
                        answer.len()
                    );
                    let _ = stream.write_all(response.as_bytes());
                    let _ = stream.shutdown(std::net::Shutdown::Both);
                }
            });
        }
    });

    Stub {
        address,
        requests,
        _server: server,
    }
}

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "permguard-cli-stub-{name}-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("the scratch directory is created");
    dir
}

fn run(workdir: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_permguard"))
        .arg("-w")
        .arg(workdir)
        .args(args)
        .env("PERMGUARD_CONFIG", workdir.join("cli-config.yml"))
        .env("NO_COLOR", "1")
        .output()
        .expect("the binary runs")
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn zone_json(id: &str, name: &str) -> String {
    format!(r#"{{"id":"{id}","name":"{name}","created_at":1,"updated_at":1,"revision":1}}"#)
}

#[test]
fn zones_commands_speak_to_a_server_end_to_end() {
    let mut routes = HashMap::new();
    routes.insert(
        ("GET", "/v1/zones"),
        (
            200,
            format!(
                "[{},{}]",
                zone_json("z-1", "acme"),
                zone_json("z-2", "beta")
            ),
        ),
    );
    routes.insert(("POST", "/v1/zones"), (200, zone_json("z-3", "gamma")));
    routes.insert(("GET", "/v1/zones/acme"), (200, zone_json("z-1", "acme")));
    routes.insert(
        ("PATCH", "/v1/zones/acme"),
        (200, zone_json("z-1", "renamed")),
    );
    routes.insert(("GET", "/v1/zones/z-2"), (200, zone_json("z-2", "beta")));
    routes.insert(("DELETE", "/v1/zones/z-2"), (200, zone_json("z-2", "beta")));
    routes.insert(("GET", "/v1/zones/missing"), (
        404,
        r#"{"class":"not_found","code":"zone_not_found","message":"nothing answers to missing"}"#
            .to_owned(),
    ));
    let stub = serve(routes);
    let endpoint = format!("http://{}", stub.address);
    let dir = scratch("zones");

    let list = run(
        &dir,
        &["--endpoint", &endpoint, "-o", "json", "zones", "list"],
    );
    assert!(list.status.success(), "{}", stderr(&list));
    assert!(stdout(&list).contains("acme"), "{}", stdout(&list));

    let create = run(&dir, &["--endpoint", &endpoint, "zones", "create", "gamma"]);
    assert!(create.status.success(), "{}", stderr(&create));
    assert!(stdout(&create).contains("gamma"));

    let get = run(
        &dir,
        &[
            "--endpoint",
            &endpoint,
            "-o",
            "yaml",
            "zones",
            "get",
            "acme",
        ],
    );
    assert!(get.status.success(), "{}", stderr(&get));

    let rename = run(
        &dir,
        &[
            "--endpoint",
            &endpoint,
            "zones",
            "update",
            "acme",
            "--name",
            "renamed",
        ],
    );
    assert!(rename.status.success(), "{}", stderr(&rename));

    let delete = run(&dir, &["--endpoint", &endpoint, "zones", "delete", "z-2"]);
    assert!(delete.status.success(), "{}", stderr(&delete));

    // A refusal carries the server's class and code and exits as usage.
    let missing = run(&dir, &["--endpoint", &endpoint, "zones", "get", "missing"]);
    assert_eq!(missing.status.code(), Some(64));
    assert!(
        stderr(&missing).contains("nothing answers"),
        "{}",
        stderr(&missing)
    );
}

#[test]
fn ledgers_commands_speak_to_a_server_end_to_end() {
    let ledger = r#"{"id":"l-1","zone_id":"z-1","name":"main-ledger","default_ref":"main","created_at":1,"updated_at":1,"revision":1,"state":"active"}"#;
    let mut routes = HashMap::new();
    routes.insert(
        ("GET", "/v1/zones/acme/ledgers"),
        (200, format!("[{ledger}]")),
    );
    routes.insert(("POST", "/v1/zones/acme/ledgers"), (200, ledger.to_owned()));
    routes.insert(
        ("GET", "/v1/zones/acme/ledgers/main-ledger"),
        (200, ledger.to_owned()),
    );
    routes.insert(
        ("PATCH", "/v1/zones/acme/ledgers/main-ledger"),
        (200, ledger.to_owned()),
    );
    routes.insert(
        ("DELETE", "/v1/zones/acme/ledgers/main-ledger"),
        (200, ledger.to_owned()),
    );
    let stub = serve(routes);
    let endpoint = format!("http://{}", stub.address);
    let dir = scratch("ledgers");

    for (args, expect) in [
        (vec!["ledgers", "list", "--zone", "acme"], "main-ledger"),
        (
            vec!["ledgers", "create", "main-ledger", "--zone", "acme"],
            "main-ledger",
        ),
        (
            vec!["ledgers", "get", "main-ledger", "--zone", "acme"],
            "l-1",
        ),
        (
            vec![
                "ledgers",
                "update",
                "main-ledger",
                "--zone",
                "acme",
                "--name",
                "renamed",
            ],
            "l-1",
        ),
        (
            vec!["ledgers", "delete", "main-ledger", "--zone", "acme"],
            "l-1",
        ),
    ] {
        let mut full = vec!["--endpoint", endpoint.as_str()];
        full.extend(args.iter().copied());
        let output = run(&dir, &full);
        assert!(output.status.success(), "{args:?}: {}", stderr(&output));
        assert!(
            stdout(&output).contains(expect),
            "{args:?}: {}",
            stdout(&output)
        );
    }
}

/// WP-7.3a, owner decision of 2026-10-20: a rename or a delete names the revision a read just
/// before answered, or the one `--expected-revision` gave without reading; every change carries a
/// fresh request id.
#[test]
fn the_cli_renames_with_the_revision_it_read() {
    let zone = r#"{"id":"z-1","name":"acme","created_at":1,"updated_at":1,"revision":7}"#;
    let ledger = r#"{"id":"l-1","zone_id":"z-1","name":"main-ledger","default_ref":"main","created_at":1,"updated_at":1,"revision":4}"#;
    let mut routes = HashMap::new();
    routes.insert(("GET", "/v1/zones/acme"), (200, zone.to_owned()));
    routes.insert(("PATCH", "/v1/zones/acme"), (200, zone.to_owned()));
    routes.insert(("DELETE", "/v1/zones/acme"), (200, zone.to_owned()));
    let path = "/v1/zones/acme/ledgers/main-ledger";
    routes.insert(("GET", path), (200, ledger.to_owned()));
    routes.insert(("PATCH", path), (200, ledger.to_owned()));
    routes.insert(("DELETE", path), (200, ledger.to_owned()));
    let stub = serve(routes);
    let endpoint = format!("http://{}", stub.address);
    let dir = scratch("revisions");
    let sent = |args: &[&str]| {
        stub.requests.lock().expect("the log").clear();
        let mut full = vec!["--endpoint", endpoint.as_str(), "-o", "json"];
        full.extend(args);
        let output = run(&dir, &full);
        assert!(output.status.success(), "{args:?}: {}", stderr(&output));
        stub.requests.lock().expect("the log").clone()
    };
    let body = |request: &str| -> serde_json::Value {
        serde_json::from_str(request.splitn(3, ' ').nth(2).expect("a body")).expect("JSON")
    };

    let read_first = sent(&["zones", "update", "acme", "--name", "renamed"]);
    assert_eq!(read_first.len(), 2, "{read_first:?}");
    assert!(read_first[0].starts_with("GET /v1/zones/acme "));
    let rename = body(&read_first[1]);
    assert_eq!(rename["expected_revision"], 7);
    assert_eq!(rename["name"], "renamed");
    let first_id = rename["request_id"]
        .as_str()
        .expect("a request id")
        .to_owned();
    assert_eq!(first_id.len(), 32);

    let given = sent(&[
        "zones",
        "update",
        "acme",
        "--name",
        "renamed",
        "--expected-revision",
        "3",
    ]);
    assert_eq!(given.len(), 1, "no read: {given:?}");
    assert_eq!(body(&given[0])["expected_revision"], 3);
    assert_ne!(
        body(&given[0])["request_id"],
        first_id.as_str(),
        "a fresh id"
    );

    let delete = sent(&["zones", "delete", "acme"]);
    assert!(
        delete[1].starts_with("DELETE /v1/zones/acme?"),
        "{delete:?}"
    );
    assert!(delete[1].contains("expected_revision=7"), "{delete:?}");
    assert!(delete[1].contains("request_id="), "{delete:?}");

    let ledger_rename = sent(&[
        "ledgers",
        "update",
        "main-ledger",
        "--zone",
        "acme",
        "--name",
        "renamed",
    ]);
    assert_eq!(body(&ledger_rename[1])["expected_revision"], 4);
    let ledger_delete = sent(&[
        "ledgers",
        "delete",
        "main-ledger",
        "--zone",
        "acme",
        "--expected-revision",
        "9",
    ]);
    assert_eq!(ledger_delete.len(), 1, "{ledger_delete:?}");
    assert!(
        ledger_delete[0].contains("expected_revision=9"),
        "{ledger_delete:?}"
    );

    // The revision is reported, what an operator gives back as `--expected-revision`.
    let shown = run(
        &dir,
        &[
            "--endpoint",
            &endpoint,
            "-o",
            "json",
            "zones",
            "get",
            "acme",
        ],
    );
    let shown: serde_json::Value = serde_json::from_slice(&shown.stdout).expect("JSON");
    assert_eq!(shown["revision"], 7);
}

/// WP-7.3b, owner decision of 2026-10-21: `ledgers archive` and `restore` post the revision a read
/// just before answered, or the one `--expected-revision` gave, with a fresh request id; the
/// report shows the state.
#[test]
fn the_cli_archives_and_restores_with_the_revision_it_read() {
    let path = "/v1/zones/acme/ledgers/main-ledger";
    let ledger = |state: &str, revision: u64| {
        format!(
            r#"{{"id":"l-1","zone_id":"z-1","name":"main-ledger","default_ref":"main","created_at":1,"updated_at":1,"revision":{revision},"state":"{state}"}}"#
        )
    };
    let mut routes = HashMap::new();
    routes.insert(
        ("GET".to_owned(), path.to_owned()),
        (200, ledger("active", 6)),
    );
    routes.insert(
        ("POST".to_owned(), format!("{path}/archive")),
        (200, ledger("archived", 7)),
    );
    routes.insert(
        ("POST".to_owned(), format!("{path}/restore")),
        (200, ledger("active", 8)),
    );
    let stub = serve_owned(routes);
    let endpoint = format!("http://{}", stub.address);
    let dir = scratch("archive");
    let sent = |args: &[&str]| {
        stub.requests.lock().expect("the log").clear();
        let mut full = vec!["--endpoint", endpoint.as_str(), "-o", "json"];
        full.extend(args);
        let output = run(&dir, &full);
        assert!(output.status.success(), "{args:?}: {}", stderr(&output));
        let report: serde_json::Value = serde_json::from_slice(&output.stdout).expect("JSON");
        (stub.requests.lock().expect("the log").clone(), report)
    };
    let body = |request: &str| -> serde_json::Value {
        serde_json::from_str(request.splitn(3, ' ').nth(2).expect("a body")).expect("JSON")
    };

    let (requests, report) = sent(&["ledgers", "archive", "main-ledger", "--zone", "acme"]);
    assert_eq!(requests.len(), 2, "{requests:?}");
    assert!(requests[0].starts_with(&format!("GET {path} ")));
    assert!(requests[1].starts_with(&format!("POST {path}/archive ")));
    let archive = body(&requests[1]);
    assert_eq!(archive["expected_revision"], 6);
    assert_eq!(archive["request_id"].as_str().map(str::len), Some(32));
    assert_eq!(
        (report["action"].as_str(), report["state"].as_str()),
        (Some("archived"), Some("archived"))
    );

    let (requests, report) = sent(&[
        "ledgers",
        "restore",
        "main-ledger",
        "--zone",
        "acme",
        "--expected-revision",
        "7",
    ]);
    assert_eq!(requests.len(), 1, "no read: {requests:?}");
    assert_eq!(body(&requests[0])["expected_revision"], 7);
    assert_eq!(
        (report["action"].as_str(), report["state"].as_str()),
        (Some("restored"), Some("active"))
    );
}

#[test]
fn remote_add_verifies_discovery_before_remembering() {
    let mut routes = HashMap::new();
    routes.insert(
        ("GET", "/.well-known/server-configuration"),
        (
            200,
            r#"{"plane":"control-plane","transports":{"http":true,"grpc":true}}"#.to_owned(),
        ),
    );
    let stub = serve(routes);
    let endpoint = format!("http://{}", stub.address);
    let dir = scratch("remote-add");
    std::fs::write(dir.join("manifest.yml"), "metadata:\n  kind: policy\n  name: x\nruntimes:\n  cedar:\n    language: { name: cedar, constraint: \">=4.0.0\" }\n    engine: { name: permguard, constraint: \">=0.1.0\" }\npartitions:\n  app: { runtime: cedar, schema: false }\nprofiles:\n  default: { type: permguard.api.pdp.native.v1, partitions: [app] }\n").unwrap();
    assert!(run(&dir, &["init", "x"]).status.success());

    let add = run(&dir, &["remote", "add", "origin", &endpoint]);
    assert!(add.status.success(), "{}", stderr(&add));
    assert!(
        stdout(&add).contains("discovery verified"),
        "{}",
        stdout(&add)
    );

    let list = run(&dir, &["-o", "json", "remote", "list"]);
    assert!(stdout(&list).contains(&endpoint), "{}", stdout(&list));

    let remove = run(&dir, &["remote", "remove", "origin"]);
    assert!(remove.status.success(), "{}", stderr(&remove));

    // A URL that answers, but is not a Permguard plane: refused.
    let mut routes = HashMap::new();
    routes.insert(
        ("GET", "/.well-known/server-configuration"),
        (200, r#"{"hello":"world"}"#.to_owned()),
    );
    let imposter = serve(routes);
    let add = run(
        &dir,
        &[
            "remote",
            "add",
            "origin",
            &format!("http://{}", imposter.address),
        ],
    );
    assert_eq!(add.status.code(), Some(64));
    assert!(
        stderr(&add).contains("not with a Permguard plane"),
        "{}",
        stderr(&add)
    );
}

#[test]
fn inspect_reads_both_planes_and_gates_on_readiness() {
    let mut control = HashMap::new();
    control.insert(
        ("GET", "/version"),
        (
            200,
            r#"{"plane":"control-plane","product":"Permguard","version":"0.1.0","commit":"abc"}"#
                .to_owned(),
        ),
    );
    control.insert(
        ("GET", "/health"),
        (200, r#"{"live":true,"ready":true}"#.to_owned()),
    );
    let control = serve(control);

    let mut data = HashMap::new();
    data.insert(
        ("GET", "/version"),
        (
            200,
            r#"{"plane":"data-plane","product":"Permguard","version":"0.1.0","commit":"abc"}"#
                .to_owned(),
        ),
    );
    data.insert(
        ("GET", "/health"),
        (200, r#"{"live":true,"ready":false}"#.to_owned()),
    );
    let data = serve(data);

    let dir = scratch("inspect");
    let output = run(
        &dir,
        &[
            "--endpoint",
            &format!("http://{}", control.address),
            "--data-endpoint",
            &format!("http://{}", data.address),
            "-o",
            "json",
            "inspect",
        ],
    );

    // Planes answered and not all are ready: the documented exit status 2.
    assert_eq!(output.status.code(), Some(2), "{}", stderr(&output));
    let parsed: serde_json::Value = serde_json::from_str(&stdout(&output)).expect("inspect JSON");
    assert_eq!(parsed["planes"].as_array().expect("planes").len(), 2);
}

/// The three layers of a discovery chain, each on a stub of its own: the interfaces' documents,
/// the plane's (linking to them), and the process's (linking to the plane); the decision log's
/// interface answers its header, the event store's is retired.
struct Chain {
    process: Stub,
    plane: Stub,
    _interfaces: Stub,
}

fn chain() -> Chain {
    let decisions = "/.well-known/permguard-decisions-native-v1-configuration";
    let events = "/.well-known/permguard-events-native-v1alpha1-configuration";
    let mut routes = HashMap::new();
    routes.insert(
        ("GET".to_owned(), decisions.to_owned()),
        (
            200,
            r#"{"interface":"permguard.api.decisions.native.v1","version":"0.1.0","component":"control-plane","state":"serving","stage":"v1","limits":{"max_records":1000}}"#
                .to_owned(),
        ),
    );
    routes.insert(
        ("GET".to_owned(), events.to_owned()),
        (
            400,
            r#"{"class":"validation","code":"interface_retired","message":"retired"}"#.to_owned(),
        ),
    );
    let interfaces = serve_owned(routes);
    let at = |path: &str| format!("http://{}{path}", interfaces.address);
    let plane_document = serde_json::json!({
        "plane": "control-plane",
        "state": "serving",
        "jwks_uri": "http://x/keys",
        "interfaces": {
            "permguard.api.decisions.native.v1": {"configuration": at(decisions), "stage": "v1"},
            "permguard.api.events.native.v1alpha1": {
                "configuration": at(events),
                "stage": "deprecated",
                "sunset": "2027-06-30T00:00:00Z"
            }
        }
    });
    let mut routes = HashMap::new();
    routes.insert(
        (
            "GET".to_owned(),
            "/.well-known/server-configuration".to_owned(),
        ),
        (200, plane_document.to_string()),
    );
    let plane = serve_owned(routes);
    let process_document = serde_json::json!({
        "host_id": "01a00000-0000-7000-8000-000000000001",
        "state": "serving",
        "planes": {
            "control-plane": {
                "state": "ready",
                "server_configuration": format!("http://{}/.well-known/server-configuration", plane.address)
            },
            "data-plane": {"state": "load", "grpc_endpoint": "grpc://127.0.0.1:7444"}
        }
    });
    let mut routes = HashMap::new();
    routes.insert(
        (
            "GET".to_owned(),
            "/.well-known/server-configuration".to_owned(),
        ),
        (200, process_document.to_string()),
    );
    Chain {
        process: serve_owned(routes),
        plane,
        _interfaces: interfaces,
    }
}

/// WP-7.4b, owner decision of 2026-10-21: `discover` walks from the process document to each
/// plane and each interface, the plane's own phase winning over the process's report of it; a
/// retired interface is shown, not an error, and a deprecated one warned.
#[test]
fn discover_walks_the_chain_from_the_process_document() {
    let chain = chain();
    let dir = scratch("discover");
    let url = format!("http://{}", chain.process.address);
    let output = run(&dir, &["-o", "json", "discover", &url]);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    let report: serde_json::Value = serde_json::from_str(&stdout(&output)).expect("JSON");
    assert_eq!(
        report["process"]["host_id"],
        "01a00000-0000-7000-8000-000000000001"
    );
    assert_eq!(report["process"]["state"], "serving");
    let control = &report["planes"][0];
    assert_eq!(control["plane"], "control-plane");
    assert_eq!(control["state"], "serving", "the plane's own document");
    let decisions = &control["interfaces"][0];
    assert_eq!(decisions["id"], "permguard.api.decisions.native.v1");
    assert_eq!(decisions["header"]["stage"], "v1");
    assert_eq!(decisions["header"]["limits"]["max_records"], 1000);
    let events = &control["interfaces"][1];
    assert_eq!(events["retired"], true);
    assert_eq!(events["sunset"], "2027-06-30T00:00:00Z");
    assert!(events.get("unreachable").is_none());
    let data = &report["planes"][1];
    assert_eq!(
        (data["state"].as_str(), data["grpc_endpoint"].as_str()),
        (Some("load"), Some("grpc://127.0.0.1:7444"))
    );
    assert_eq!(report["complete"], true);

    let text = run(&dir, &["discover", &url]);
    let text = stdout(&text);
    assert!(
        text.contains("deprecated, served until 2027-06-30T00:00:00Z"),
        "{text}"
    );
    assert!(text.contains("retired"), "{text}");
}

/// WP-7.4b: from a plane's address the walk starts at that plane.
#[test]
fn discover_starts_from_a_plane_document() {
    let chain = chain();
    let dir = scratch("discover-plane");
    let output = run(
        &dir,
        &[
            "-o",
            "json",
            "discover",
            &format!("http://{}", chain.plane.address),
        ],
    );
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    let report: serde_json::Value = serde_json::from_str(&stdout(&output)).expect("JSON");
    assert!(report.get("process").is_none());
    assert_eq!(report["planes"][0]["plane"], "control-plane");
    assert_eq!(
        report["planes"][0]["interfaces"].as_array().map(Vec::len),
        Some(2)
    );
}

/// WP-7.4b, owner decision of 2026-10-21: a link that does not answer is shown and makes the
/// exit 69; an address that answers nothing is 69 too.
#[test]
fn discover_reports_a_link_that_does_not_answer() {
    let mut routes = HashMap::new();
    routes.insert(
        ("GET", "/.well-known/server-configuration"),
        (
            200,
            r#"{"state":"serving","planes":{"control-plane":{"state":"ready","server_configuration":"http://127.0.0.1:1/.well-known/server-configuration"}}}"#
                .to_owned(),
        ),
    );
    let process = serve(routes);
    let dir = scratch("discover-down");
    let output = run(
        &dir,
        &[
            "-o",
            "json",
            "discover",
            &format!("http://{}", process.address),
        ],
    );
    assert_eq!(output.status.code(), Some(69), "{}", stderr(&output));
    let report: serde_json::Value = serde_json::from_str(&stdout(&output)).expect("JSON");
    assert!(report["planes"][0]["unreachable"].is_string(), "{report}");
    assert_eq!(report["complete"], false);

    let nothing = run(&dir, &["discover", "http://127.0.0.1:1"]);
    assert_eq!(nothing.status.code(), Some(69), "{}", stderr(&nothing));
    let grpc = run(&dir, &["discover", "grpc://127.0.0.1:1"]);
    assert_ne!(grpc.status.code(), Some(0), "only HTTP is walked");
}

/// WP-7.4b, after the review: every link the walk could not follow is a line of the report and
/// makes the exit 69: an interface answering 404, one whose link names no configuration, a plane
/// linked over a scheme the walk does not read. An address already read is not read again, and a
/// control sequence a server sends reaches the terminal escaped.
#[test]
fn discover_reports_every_link_it_could_not_follow() {
    let nothing = serve(HashMap::new());
    let missing = format!("http://{}/missing", nothing.address);
    let plane_document = serde_json::json!({
        "plane": "control-plane",
        "state": "serving",
        "interfaces": {
            "a.first": {"configuration": missing, "stage": "v1"},
            "b.again": {"configuration": missing, "stage": "v1"},
            "c.nowhere": {"stage": "v1"}
        }
    });
    let mut routes = HashMap::new();
    routes.insert(
        (
            "GET".to_owned(),
            "/.well-known/server-configuration".to_owned(),
        ),
        (200, plane_document.to_string()),
    );
    let plane = serve_owned(routes);
    let process_document = serde_json::json!({
        "state": "serving",
        "planes": {
            "control-plane": {
                "state": "ready",
                "server_configuration": format!("http://{}/.well-known/server-configuration", plane.address)
            },
            "elsewhere\u{1b}[31m": {"state": "ready", "server_configuration": "ftp://127.0.0.1:1/x"}
        }
    });
    let mut routes = HashMap::new();
    routes.insert(
        (
            "GET".to_owned(),
            "/.well-known/server-configuration".to_owned(),
        ),
        (200, process_document.to_string()),
    );
    let process = serve_owned(routes);
    let dir = scratch("discover-links");
    let url = format!("http://{}", process.address);

    let output = run(&dir, &["-o", "json", "discover", &url]);
    assert_eq!(output.status.code(), Some(69), "{}", stderr(&output));
    let report: serde_json::Value = serde_json::from_str(&stdout(&output)).expect("JSON");
    let control = &report["planes"][0];
    let interfaces = &control["interfaces"];
    assert!(
        interfaces[0]["unreachable"]
            .as_str()
            .is_some_and(|why| why.contains("answered 404")),
        "{report}"
    );
    assert_eq!(interfaces[0]["retired"], serde_json::Value::Null);
    assert_eq!(interfaces[1]["repeated"], true, "{report}");
    assert!(interfaces[1].get("unreachable").is_none(), "{report}");
    assert_eq!(
        interfaces[2]["unreachable"],
        "its link names no configuration"
    );
    let elsewhere = &report["planes"][1];
    assert!(
        elsewhere["unreachable"]
            .as_str()
            .is_some_and(|why| why.contains("not an HTTP or HTTPS address")),
        "{report}"
    );
    assert_eq!(report["complete"], false);
    // The 404 address is read once, though two interfaces link to it.
    assert_eq!(
        nothing.requests.lock().expect("the log").len(),
        1,
        "an address already read is not read again"
    );

    let yaml = run(&dir, &["-o", "yaml", "discover", &url]);
    assert_eq!(yaml.status.code(), Some(69), "{}", stderr(&yaml));
    assert!(
        stdout(&yaml).contains("complete: false"),
        "{}",
        stdout(&yaml)
    );

    let text = run(&dir, &["discover", &url]);
    let text = stdout(&text);
    assert!(
        !text.contains('\u{1b}'),
        "a control sequence reached the terminal"
    );
    assert!(text.contains("elsewhere\\u{1b}[31m"), "{text}");
    assert!(text.contains("already read in this walk"), "{text}");
    assert!(text.contains("some links did not answer"), "{text}");

    // From the plane's own address every plane answers: the interfaces alone leave the walk
    // incomplete.
    let output = run(
        &dir,
        &[
            "-o",
            "json",
            "discover",
            &format!("http://{}", plane.address),
        ],
    );
    assert_eq!(output.status.code(), Some(69), "{}", stderr(&output));
    let report: serde_json::Value = serde_json::from_str(&stdout(&output)).expect("JSON");
    assert!(report["planes"][0].get("unreachable").is_none(), "{report}");
    assert_eq!(report["complete"], false);
}

/// WP-7.4b, after the review: a document cannot hold the walk with links; the planes past 64 and
/// the interfaces past 256 are counted, not followed.
#[test]
fn discover_follows_a_bounded_number_of_links() {
    let interfaces: serde_json::Map<String, serde_json::Value> = (0..257)
        .map(|n| (format!("i{n:03}"), serde_json::json!({"stage": "v1"})))
        .collect();
    let mut routes = HashMap::new();
    routes.insert(
        (
            "GET".to_owned(),
            "/.well-known/server-configuration".to_owned(),
        ),
        (
            200,
            serde_json::json!({"plane": "control-plane", "interfaces": interfaces}).to_string(),
        ),
    );
    let plane = serve_owned(routes);
    let mut planes = serde_json::Map::new();
    planes.insert(
        "control-plane".to_owned(),
        serde_json::json!({
            "server_configuration": format!("http://{}/.well-known/server-configuration", plane.address)
        }),
    );
    for n in 0..64 {
        planes.insert(format!("p{n:02}"), serde_json::json!({"state": "ready"}));
    }
    let mut routes = HashMap::new();
    routes.insert(
        (
            "GET".to_owned(),
            "/.well-known/server-configuration".to_owned(),
        ),
        (
            200,
            serde_json::json!({"state": "serving", "planes": planes}).to_string(),
        ),
    );
    let process = serve_owned(routes);
    let dir = scratch("discover-bounds");
    let output = run(
        &dir,
        &[
            "-o",
            "json",
            "discover",
            &format!("http://{}", process.address),
        ],
    );
    let report: serde_json::Value = serde_json::from_str(&stdout(&output)).expect("JSON");
    assert_eq!(report["planes"].as_array().map(Vec::len), Some(64));
    assert_eq!(report["not_followed"], 1);
    let control = &report["planes"][0];
    assert_eq!(control["plane"], "control-plane");
    assert_eq!(control["interfaces"].as_array().map(Vec::len), Some(256));
    assert_eq!(control["not_followed"], 1);
}

/// WP-7.4b, owner decision of 2026-10-21: discovery is unauthenticated, so the operator's token
/// is never sent. A token handed to the client would be refused over plain HTTP; the walk
/// completes because the token was left out.
#[test]
fn discover_never_sends_the_operators_token() {
    let chain = chain();
    let dir = scratch("discover-token");
    let token = dir.join("token");
    std::fs::write(&token, "secret-token").expect("the token is written");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&token, std::fs::Permissions::from_mode(0o600))
            .expect("the token is owner-only");
    }
    let url = format!("http://{}", chain.process.address);
    let token = token.to_string_lossy().into_owned();
    let output = run(
        &dir,
        &["--token-file", &token, "-o", "json", "discover", &url],
    );
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    let everything = format!("{}{}", stdout(&output), stderr(&output));
    assert!(!everything.contains("secret-token"));
}

/// WP-7.4b, after the review: an address the walk does not read is the operator's mistake, a
/// usage error, exit 64; a trailing well-known path is the same address.
#[test]
fn discover_refuses_an_address_it_does_not_walk() {
    let dir = scratch("discover-usage");
    for address in ["grpc://127.0.0.1:1", "ftp://127.0.0.1:1", "127.0.0.1:1"] {
        let output = run(&dir, &["discover", address]);
        assert_eq!(
            output.status.code(),
            Some(64),
            "{address}: {}",
            stderr(&output)
        );
    }
    let chain = chain();
    let output = run(
        &dir,
        &[
            "-o",
            "json",
            "discover",
            &format!(
                "http://{}/.well-known/server-configuration/",
                chain.plane.address
            ),
        ],
    );
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    let report: serde_json::Value = serde_json::from_str(&stdout(&output)).expect("JSON");
    assert_eq!(report["planes"][0]["plane"], "control-plane");
}

/// WP-7.4b, owner decision of 2026-10-21: `inspect` reports each plane's phase and the interfaces
/// its document lists with their stage, a deprecated one warned with its sunset.
#[test]
fn inspect_reports_each_plane_state_and_its_interfaces() {
    let plane = |name: &str, state: &str| {
        let mut routes = HashMap::new();
        routes.insert(
            ("GET".to_owned(), "/version".to_owned()),
            (
                200,
                format!(
                    r#"{{"plane":"{name}","product":"Permguard","version":"0.1.0","commit":"abc"}}"#
                ),
            ),
        );
        routes.insert(
            ("GET".to_owned(), "/health".to_owned()),
            (
                200,
                format!(r#"{{"live":true,"ready":true,"state":"{state}"}}"#),
            ),
        );
        routes.insert(
            ("GET".to_owned(), "/.well-known/server-configuration".to_owned()),
            (
                200,
                format!(
                    r#"{{"plane":"{name}","state":"{state}","interfaces":{{"permguard.api.old.v1":{{"configuration":"http://x","stage":"deprecated","sunset":"2027-06-30T00:00:00Z"}}}}}}"#
                ),
            ),
        );
        serve_owned(routes)
    };
    let control = plane("control-plane", "serving");
    let data = plane("data-plane", "ready");
    let dir = scratch("inspect-state");
    let args = |format: Option<&'static str>| {
        let mut args = vec![
            "--endpoint".to_owned(),
            format!("http://{}", control.address),
            "--data-endpoint".to_owned(),
            format!("http://{}", data.address),
        ];
        if let Some(format) = format {
            args.extend(["-o".to_owned(), format.to_owned()]);
        }
        args.push("inspect".to_owned());
        args
    };
    let json = args(Some("json"));
    let output = run(&dir, &json.iter().map(String::as_str).collect::<Vec<_>>());
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    let report: serde_json::Value = serde_json::from_str(&stdout(&output)).expect("JSON");
    assert_eq!(report["planes"][0]["state"], "serving");
    assert_eq!(report["planes"][1]["state"], "ready");
    assert_eq!(
        report["planes"][0]["interfaces"][0],
        serde_json::json!({"id": "permguard.api.old.v1", "stage": "deprecated", "sunset": "2027-06-30T00:00:00Z"})
    );
    let text = args(None);
    let output = run(&dir, &text.iter().map(String::as_str).collect::<Vec<_>>());
    let text = stdout(&output);
    assert!(text.contains("state:    serving"), "{text}");
    assert!(
        text.contains("permguard.api.old.v1 is deprecated, served until 2027-06-30T00:00:00Z"),
        "{text}"
    );
}

#[test]
fn inspect_with_nobody_listening_exits_unreachable() {
    let dir = scratch("inspect-down");
    let output = run(
        &dir,
        &[
            "--endpoint",
            "http://127.0.0.1:1",
            "--data-endpoint",
            "http://127.0.0.1:1",
            "inspect",
        ],
    );

    assert_eq!(output.status.code(), Some(1), "{}", stderr(&output));
}

/// `permguard test --remote` asks a plane the cases instead of deciding them here, and judges the
/// answer the way the local run judges its own.
///
/// The point of the flag is the case this test builds: sources that are right, and a plane that is
/// serving something else. A local run passes and must; a remote run has to fail, and has to say
/// that what answered is not what these sources contain.
#[test]
fn test_remote_asks_the_plane_and_reports_what_it_answered() {
    let dir = scratch("test-remote");

    // A workspace with one Cedar policy, and a case for it.
    std::fs::create_dir_all(dir.join("cedar")).expect("the partition directory is created");
    std::fs::create_dir_all(dir.join("tests")).expect("the cases directory is created");
    std::fs::create_dir_all(dir.join("requests")).expect("the requests directory is created");
    std::fs::write(
        dir.join("cedar/readers.cedar"),
        "@alias(\"readers\")\npermit (principal, action == Action::\"read\", resource);\n",
    )
    .expect("the policy is written");
    std::fs::write(
        dir.join("requests/read.json"),
        r#"{"subject":{"type":"User","id":"alice"},"action":{"name":"read"},
            "resource":{"type":"Document","id":"budget"}}"#,
    )
    .expect("the request is written");
    std::fs::write(
        dir.join("tests/cases.yml"),
        "- name: alice reads\n  request: ../requests/read.json\n  expect: { decision: permit, policies: [readers] }\n",
    )
    .expect("the cases are written");

    // The plane permits, but cites a policy this workspace does not contain: the ledger it is
    // serving is not the one these sources describe.
    let mut routes = HashMap::new();
    routes.insert(
        (
            "GET".to_owned(),
            "/.well-known/server-configuration".to_owned(),
        ),
        (
            200,
            r#"{"product":"Permguard","version":"0.1.0"}"#.to_owned(),
        ),
    );
    routes.insert(
        ("POST".to_owned(), "/access/v1/evaluation".to_owned()),
        (
            200,
            r#"{"decision":true,"context":{"id":"01","policies":["a-policy-from-another-commit"]}}"#
                .to_owned(),
        ),
    );
    let stub = serve_owned(routes);
    let endpoint = format!("http://{}", stub.address);

    run(&dir, &["init", "remote-cases"]);

    let output = run(
        &dir,
        &[
            "test",
            "--remote",
            "--zone",
            "delivery",
            "--ledger",
            "release-pipeline",
            "--data-endpoint",
            &endpoint,
        ],
    );

    assert_eq!(
        output.status.code(),
        Some(2),
        "a plane serving another commit is a failing run: {}",
        stderr(&output)
    );
    assert!(
        stdout(&output).contains("a-policy-from-another-commit"),
        "the report names what the plane cited: {}",
        stdout(&output)
    );
    assert!(
        stdout(&output).contains("no policy of this workspace"),
        "and says the plane is not deciding with these sources: {}",
        stdout(&output)
    );
    assert!(
        stdout(&output).contains(&endpoint),
        "and says which plane it asked: {}",
        stdout(&output)
    );

    // The same cases, decided here, pass: the sources are not what is wrong.
    let output = run(&dir, &["test"]);
    assert!(
        output.status.success(),
        "the local run judges the sources, and they are right: {}",
        stdout(&output)
    );
}

/// A plane's answer is checked before it is believed.
///
/// Reading a missing `decision` as `false` would let a body of `{}` satisfy a case expecting a
/// deny — a run that goes green against a plane that answered nothing at all. Each of these bodies
/// is a 200 that is not a decision, and each has to fail the case as a protocol problem rather than
/// be judged as one.
#[test]
fn test_remote_refuses_an_answer_that_is_not_a_decision() {
    for (what, body) in [
        ("an empty object", "{}"),
        ("a body that is not an object", "[]"),
        ("a decision that is not a boolean", r#"{"decision":"yes"}"#),
        (
            "a context that is not an object",
            r#"{"decision":false,"context":"invalid"}"#,
        ),
        (
            "a reason that is not an object",
            r#"{"decision":false,"context":{"reason_admin":"nope"}}"#,
        ),
        (
            "a reason code that is not a string",
            r#"{"decision":false,"context":{"reason_admin":{"code":7,"message":[]}}}"#,
        ),
        (
            "a reason with no message",
            r#"{"decision":false,"context":{"reason_admin":{"code":"500"}}}"#,
        ),
        (
            "policies that are null",
            r#"{"decision":false,"context":{"policies":null}}"#,
        ),
        (
            "an evaluation that is not a decision",
            r#"{"decision":false,"evaluations":[{"request_id":"read"}]}"#,
        ),
        (
            "policies that are not names",
            r#"{"decision":false,"context":{"policies":[{"id":"x"}]}}"#,
        ),
        (
            "policies that are not an array",
            r#"{"decision":false,"context":{"policies":"readers"}}"#,
        ),
    ] {
        let dir = scratch("remote-malformed");
        remote_workspace(&dir, "expect: { decision: deny, policies: [] }");

        let mut routes = HashMap::new();
        routes.insert(
            ("POST".to_owned(), "/access/v1/evaluation".to_owned()),
            (200, body.to_owned()),
        );
        let stub = serve_owned(routes);

        let output = run(
            &dir,
            &[
                "test",
                "--remote",
                "--zone",
                "z",
                "--ledger",
                "l",
                "--data-endpoint",
                &format!("http://{}", stub.address),
            ],
        );

        assert_eq!(
            output.status.code(),
            Some(2),
            "{what} passed as a deny: {}",
            stdout(&output)
        );
        assert!(
            stdout(&output).contains("not a decision"),
            "{what} was not reported as a protocol problem: {}",
            stdout(&output)
        );
    }
}

/// `expect: { error: … }` means the same thing in both modes.
///
/// A plane answers an evaluation it could not perform with the typed refusal
/// `503 evaluation_indeterminate`, and refuses a request that is missing a field with a `4xx`
/// naming the field. Both are "the request could not be evaluated", which is what a case expecting
/// an error is asking about. A plane of an earlier release reported the first as a deny whose
/// `reason_admin` carried code `500`, and that is still read as the error it was.
#[test]
fn test_remote_carries_the_planes_refusals_into_the_expectation() {
    // An evaluation the plane could not perform: indeterminate, refused, not a deny.
    let dir = scratch("remote-error");
    remote_workspace(&dir, "expect: { error: clearance }");

    let mut routes = HashMap::new();
    routes.insert(
        ("POST".to_owned(), "/access/v1/evaluation".to_owned()),
        (
            503,
            r#"{"class":"unavailable","code":"evaluation_indeterminate",
                "message":"the request could not be evaluated: 1 partition evaluation(s) failed; this is not a deny: cedar: `clearance` does not exist"}"#
                .to_owned(),
        ),
    );
    let stub = serve_owned(routes);
    let output = run(
        &dir,
        &[
            "test",
            "--remote",
            "--zone",
            "z",
            "--ledger",
            "l",
            "--data-endpoint",
            &format!("http://{}", stub.address),
        ],
    );
    assert!(
        output.status.success(),
        "an indeterminate evaluation is the refusal the case expected: {}",
        stdout(&output)
    );

    // The same, from a plane of an earlier release: a deny whose reason says it never evaluated.
    let dir = scratch("remote-error-legacy");
    remote_workspace(&dir, "expect: { error: schema }");

    let mut routes = HashMap::new();
    routes.insert(
        ("POST".to_owned(), "/access/v1/evaluation".to_owned()),
        (
            200,
            r#"{"decision":false,"context":{"reason_admin":{"code":"500",
                "message":"the request could not be evaluated, so it is denied: cedar: does not conform to the schema"}}}"#
                .to_owned(),
        ),
    );
    let stub = serve_owned(routes);
    let output = run(
        &dir,
        &[
            "test",
            "--remote",
            "--zone",
            "z",
            "--ledger",
            "l",
            "--data-endpoint",
            &format!("http://{}", stub.address),
        ],
    );
    assert!(
        output.status.success(),
        "a 500-coded reason is the refusal the case expected: {}",
        stdout(&output)
    );

    // And a request the plane would not read at all.
    let dir = scratch("remote-refused");
    remote_workspace(&dir, "expect: { error: field_required }");

    let mut routes = HashMap::new();
    routes.insert(
        ("POST".to_owned(), "/access/v1/evaluation".to_owned()),
        (
            400,
            r#"{"class":"validation","code":"field_required","message":"`resource` is required"}"#
                .to_owned(),
        ),
    );
    let stub = serve_owned(routes);
    let output = run(
        &dir,
        &[
            "test",
            "--remote",
            "--zone",
            "z",
            "--ledger",
            "l",
            "--data-endpoint",
            &format!("http://{}", stub.address),
        ],
    );
    assert!(
        output.status.success(),
        "a refusal of what was asked is an answer a case may expect: {}",
        stdout(&output)
    );
}

/// `permguard check` against a plane that could not evaluate: the refusal, by its code, and never
/// a deny — and an input the engine rejects is the `400` the plane answers, judged by `test
/// --remote` as the error a case may expect, as the local run calls it.
#[test]
fn test_check_reports_an_indeterminate_result_as_a_refusal_not_a_deny() {
    let dir = scratch("check-indeterminate");
    remote_workspace(&dir, "expect: { error: evaluation_input_rejected }");

    let mut routes = HashMap::new();
    routes.insert(
        ("POST".to_owned(), "/access/v1/evaluation".to_owned()),
        (
            503,
            r#"{"class":"unavailable","code":"evaluation_indeterminate",
                "message":"the request could not be evaluated: 1 partition evaluation(s) failed; this is not a deny"}"#
                .to_owned(),
        ),
    );
    let stub = serve_owned(routes);
    let output = run(
        &dir,
        &[
            "check",
            "-f",
            "requests/read.json",
            "--zone",
            "z",
            "--ledger",
            "l",
            "--data-endpoint",
            &format!("http://{}", stub.address),
        ],
    );
    let said = format!("{}{}", stdout(&output), stderr(&output));
    assert!(
        !output.status.success(),
        "a refusal is not an answer: {said}"
    );
    assert!(said.contains("evaluation_indeterminate"), "{said}");
    assert!(
        !said.contains("DENY") && !said.contains("Denied"),
        "never shown as a deny: {said}"
    );

    let mut routes = HashMap::new();
    routes.insert(
        ("POST".to_owned(), "/access/v1/evaluation".to_owned()),
        (
            400,
            r#"{"class":"validation","code":"evaluation_input_rejected",
                "message":"the request could not be represented by the engine that evaluates it: 1 partition evaluation(s) failed; this is not a deny"}"#
                .to_owned(),
        ),
    );
    let stub = serve_owned(routes);
    let output = run(
        &dir,
        &[
            "test",
            "--remote",
            "--zone",
            "z",
            "--ledger",
            "l",
            "--data-endpoint",
            &format!("http://{}", stub.address),
        ],
    );
    assert!(
        output.status.success(),
        "an input the engine rejects is the refusal the case expected: {}",
        stdout(&output)
    );
}

/// A workspace with one policy, one request and one case, for the remote tests above.
fn remote_workspace(dir: &Path, expect: &str) {
    std::fs::create_dir_all(dir.join("cedar")).expect("the partition directory is created");
    std::fs::create_dir_all(dir.join("tests")).expect("the cases directory is created");
    std::fs::create_dir_all(dir.join("requests")).expect("the requests directory is created");
    std::fs::write(
        dir.join("cedar/readers.cedar"),
        "@alias(\"readers\")\npermit (principal, action == Action::\"read\", resource);\n",
    )
    .expect("the policy is written");
    std::fs::write(
        dir.join("requests/read.json"),
        r#"{"subject":{"type":"User","id":"alice"},"action":{"name":"read"},
            "resource":{"type":"Document","id":"budget"}}"#,
    )
    .expect("the request is written");
    std::fs::write(
        dir.join("tests/cases.yml"),
        format!("- name: alice reads\n  request: ../requests/read.json\n  {expect}\n"),
    )
    .expect("the cases are written");

    run(dir, &["init", "remote-cases"]);
}

/// A boxcarred request, end to end through `test --remote`: three evaluations asked, three
/// answered, and a case that names what each one must decide.
///
/// The local run and the data plane's own boxcarring were each covered; the path between them was
/// not, and a manual check protects nothing from a regression.
#[test]
fn test_remote_carries_a_boxcarred_batch_end_to_end() {
    let dir = scratch("remote-batch");
    boxcarred_workspace(
        &dir,
        "expect:\n    decision: deny\n    policies: []\n    evaluations: { read: permit, create: permit, purge: deny }",
    );

    let mut routes = HashMap::new();
    routes.insert(
        ("POST".to_owned(), "/access/v1/evaluations".to_owned()),
        (
            200,
            r#"{"decision":false,"evaluations":[
                 {"decision":true,"request_id":"read"},
                 {"decision":true,"request_id":"create"},
                 {"decision":false,"request_id":"purge"}]}"#
                .to_owned(),
        ),
    );
    let stub = serve_owned(routes);

    let args = remote_args(&stub.address);
    let output = run(
        &dir,
        &args.iter().map(String::as_str).collect::<Vec<&str>>(),
    );
    assert!(
        output.status.success(),
        "the batch was not judged as asked: {}\n{}",
        stdout(&output),
        stderr(&output)
    );
    assert!(
        stdout(&output).contains("read=permit") && stdout(&output).contains("purge=deny"),
        "the report does not show what each evaluation decided: {}",
        stdout(&output)
    );
}

/// A batch whose policies this workspace does not contain is drift, whatever its booleans say.
#[test]
fn test_remote_finds_drift_inside_a_batch() {
    let dir = scratch("remote-batch-drift");
    boxcarred_workspace(
        &dir,
        "expect:\n    decision: deny\n    evaluations: { read: permit, create: permit, purge: deny }",
    );

    let mut routes = HashMap::new();
    routes.insert(
        ("POST".to_owned(), "/access/v1/evaluations".to_owned()),
        (
            200,
            r#"{"decision":false,"evaluations":[
                 {"decision":true,"request_id":"read","context":{"policies":["from-another-commit"]}},
                 {"decision":true,"request_id":"create"},
                 {"decision":false,"request_id":"purge"}]}"#
                .to_owned(),
        ),
    );
    let stub = serve_owned(routes);

    let args = remote_args(&stub.address);
    let output = run(
        &dir,
        &args.iter().map(String::as_str).collect::<Vec<&str>>(),
    );
    assert_eq!(
        output.status.code(),
        Some(2),
        "the booleans matched and the drift was not reported: {}",
        stdout(&output)
    );
    assert!(
        stdout(&output).contains("from-another-commit")
            && stdout(&output).contains("no policy of this workspace"),
        "{}",
        stdout(&output)
    );
}

/// An answer that typechecks but is not an answer to *this* request.
#[test]
fn test_remote_refuses_a_batch_that_does_not_answer_the_request() {
    for (what, body) in [
        (
            "no evaluations at all",
            r#"{"decision":false,"evaluations":[]}"#,
        ),
        ("the evaluations missing", r#"{"decision":false}"#),
        (
            "more evaluations than were asked",
            r#"{"decision":false,"evaluations":[
                 {"decision":true,"request_id":"read"},{"decision":true,"request_id":"create"},
                 {"decision":false,"request_id":"purge"},{"decision":false,"request_id":"extra"}]}"#,
        ),
        (
            "fewer than were asked, under execute_all",
            r#"{"decision":false,"evaluations":[{"decision":false,"request_id":"read"}]}"#,
        ),
        (
            "the evaluations out of order",
            r#"{"decision":false,"evaluations":[
                 {"decision":true,"request_id":"create"},{"decision":true,"request_id":"read"},
                 {"decision":false,"request_id":"purge"}]}"#,
        ),
        (
            "a verdict its evaluations do not add up to",
            r#"{"decision":true,"evaluations":[
                 {"decision":true,"request_id":"read"},{"decision":true,"request_id":"create"},
                 {"decision":false,"request_id":"purge"}]}"#,
        ),
    ] {
        let dir = scratch("remote-batch-broken");
        boxcarred_workspace(&dir, "expect: { decision: deny }");

        let mut routes = HashMap::new();
        routes.insert(
            ("POST".to_owned(), "/access/v1/evaluations".to_owned()),
            (200, body.to_owned()),
        );
        let stub = serve_owned(routes);

        let args = remote_args(&stub.address);
        let output = run(
            &dir,
            &args.iter().map(String::as_str).collect::<Vec<&str>>(),
        );
        assert_eq!(
            output.status.code(),
            Some(2),
            "{what} passed as an answer: {}",
            stdout(&output)
        );
        assert!(
            stdout(&output).contains("not a decision"),
            "{what} was not reported as a protocol problem: {}",
            stdout(&output)
        );
    }
}

/// A workspace whose one case asks three questions in one request.
fn boxcarred_workspace(dir: &Path, expect: &str) {
    std::fs::create_dir_all(dir.join("cedar")).expect("the partition directory is created");
    std::fs::create_dir_all(dir.join("tests")).expect("the cases directory is created");
    std::fs::create_dir_all(dir.join("requests")).expect("the requests directory is created");
    std::fs::write(
        dir.join("cedar/readers.cedar"),
        "@alias(\"readers\")\npermit (principal, action == Action::\"read\", resource);\n",
    )
    .expect("the policy is written");
    std::fs::write(
        dir.join("requests/batch.json"),
        r#"{"subject":{"type":"User","id":"dora"},"resource":{"type":"Document","id":"q4"},
            "evaluations":[{"action":{"name":"read"},"request_id":"read"},
                           {"action":{"name":"create"},"request_id":"create"},
                           {"action":{"name":"purge"},"request_id":"purge"}]}"#,
    )
    .expect("the request is written");
    std::fs::write(
        dir.join("tests/cases.yml"),
        format!("- name: three in one\n  request: ../requests/batch.json\n  {expect}\n"),
    )
    .expect("the cases are written");

    run(dir, &["init", "batch-cases"]);
}

fn remote_args(address: &str) -> Vec<String> {
    vec![
        "test".to_owned(),
        "--remote".to_owned(),
        "--zone".to_owned(),
        "z".to_owned(),
        "--ledger".to_owned(),
        "l".to_owned(),
        "--data-endpoint".to_owned(),
        format!("http://{address}"),
    ]
}

/// The two stopping semantics are validated exactly, not as "any prefix will do".
///
/// Under `deny_on_first_deny` a batch ends at the first deny and not before, so the number of
/// evaluations answered is decided by the answers themselves. Accepting any prefix let a single
/// `permit` pass as a whole batch, and let a batch that kept going past its own stop pass too.
#[test]
fn test_remote_holds_a_stopping_batch_to_the_length_its_answers_imply() {
    // `deny_on_first_deny`: three asked.
    for (what, body, ok, expect) in [
        (
            "stopped at the first deny, as it must",
            r#"{"decision":false,"evaluations":[
                 {"decision":true,"request_id":"read"},{"decision":false,"request_id":"create"}]}"#,
            true,
            "expect: { decision: deny }",
        ),
        (
            "every answer a permit, so every one runs",
            r#"{"decision":true,"evaluations":[
                 {"decision":true,"request_id":"read"},{"decision":true,"request_id":"create"},
                 {"decision":true,"request_id":"purge"}]}"#,
            true,
            "expect: { decision: permit }",
        ),
        (
            "one permit offered as the whole batch",
            r#"{"decision":true,"evaluations":[{"decision":true,"request_id":"read"}]}"#,
            false,
            "expect: { decision: permit }",
        ),
        (
            "kept going past the deny that ends it",
            r#"{"decision":false,"evaluations":[
                 {"decision":false,"request_id":"read"},{"decision":true,"request_id":"create"},
                 {"decision":true,"request_id":"purge"}]}"#,
            false,
            "expect: { decision: deny }",
        ),
    ] {
        let dir = scratch("remote-stop-deny");
        stopping_workspace(&dir, "deny_on_first_deny", expect);

        let mut routes = HashMap::new();
        routes.insert(
            ("POST".to_owned(), "/access/v1/evaluations".to_owned()),
            (200, body.to_owned()),
        );
        let stub = serve_owned(routes);
        let args = remote_args(&stub.address);
        let output = run(
            &dir,
            &args.iter().map(String::as_str).collect::<Vec<&str>>(),
        );

        if ok {
            assert!(
                output.status.success(),
                "{what} was refused: {}",
                stdout(&output)
            );
        } else {
            assert_eq!(
                output.status.code(),
                Some(2),
                "{what} passed: {}",
                stdout(&output)
            );
            assert!(
                stdout(&output).contains("not a decision"),
                "{what}: {}",
                stdout(&output)
            );
        }
    }

    // `permit_on_first_permit`: the mirror image. The overall verdict under OR is the
    // disjunction, so a batch that reached a permit is a permit.
    for (what, body, ok, expect) in [
        (
            "stopped at the first permit, as it must",
            r#"{"decision":true,"evaluations":[
                 {"decision":false,"request_id":"read"},{"decision":true,"request_id":"create"}]}"#,
            true,
            "expect: { decision: permit }",
        ),
        (
            "one deny offered as the whole batch",
            r#"{"decision":false,"evaluations":[{"decision":false,"request_id":"read"}]}"#,
            false,
            "expect: { decision: deny }",
        ),
        (
            "kept going past the permit that ends it",
            r#"{"decision":true,"evaluations":[
                 {"decision":true,"request_id":"read"},{"decision":false,"request_id":"create"},
                 {"decision":false,"request_id":"purge"}]}"#,
            false,
            "expect: { decision: permit }",
        ),
    ] {
        let dir = scratch("remote-stop-permit");
        stopping_workspace(&dir, "permit_on_first_permit", expect);

        let mut routes = HashMap::new();
        routes.insert(
            ("POST".to_owned(), "/access/v1/evaluations".to_owned()),
            (200, body.to_owned()),
        );
        let stub = serve_owned(routes);
        let args = remote_args(&stub.address);
        let output = run(
            &dir,
            &args.iter().map(String::as_str).collect::<Vec<&str>>(),
        );

        if ok {
            assert!(
                output.status.success(),
                "{what} was refused: {}",
                stdout(&output)
            );
        } else {
            assert_eq!(
                output.status.code(),
                Some(2),
                "{what} passed: {}",
                stdout(&output)
            );
        }
    }
}

/// A workspace whose one case boxcars three questions under a named semantic.
fn stopping_workspace(dir: &Path, semantic: &str, expect: &str) {
    std::fs::create_dir_all(dir.join("cedar")).expect("the partition directory is created");
    std::fs::create_dir_all(dir.join("tests")).expect("the cases directory is created");
    std::fs::create_dir_all(dir.join("requests")).expect("the requests directory is created");
    std::fs::write(
        dir.join("cedar/readers.cedar"),
        "@alias(\"readers\")\npermit (principal, action == Action::\"read\", resource);\n",
    )
    .expect("the policy is written");
    std::fs::write(
        dir.join("requests/batch.json"),
        format!(
            r#"{{"subject":{{"type":"User","id":"dora"}},"resource":{{"type":"Document","id":"q4"}},
                "options":{{"evaluations_semantic":"{semantic}"}},
                "evaluations":[{{"action":{{"name":"read"}},"request_id":"read"}},
                               {{"action":{{"name":"create"}},"request_id":"create"}},
                               {{"action":{{"name":"purge"}},"request_id":"purge"}}]}}"#
        ),
    )
    .expect("the request is written");
    // What is under test is whether the answer is accepted as an answer at all, so the case
    // states the verdict the caller's own bodies imply — a case that asserted nothing would go
    // green whatever came back, which is what this suite is here to prevent.
    std::fs::write(
        dir.join("tests/cases.yml"),
        format!("- name: three in one\n  request: ../requests/batch.json\n  {expect}\n"),
    )
    .expect("the cases are written");

    run(dir, &["init", "stop-cases"]);
}
