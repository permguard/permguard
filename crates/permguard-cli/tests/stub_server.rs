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

/// A canned HTTP/1.1 answerer: method+path → (status, body). Unknown paths
/// answer 404 with the structured refusal shape.
struct Stub {
    address: String,
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

    let server = std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { break };
            let routes = Arc::clone(&routes);
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

                    let (status, answer) = routes
                        .get(&(method.clone(), path.clone()))
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
    format!(r#"{{"id":"{id}","name":"{name}","created_at":1,"updated_at":1}}"#)
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
    let ledger = r#"{"id":"l-1","zone_id":"z-1","name":"main-ledger","default_ref":"main","created_at":1,"updated_at":1}"#;
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
    std::fs::write(dir.join("manifest.yml"), "metadata:\n  kind: policy\n  name: x\nruntimes:\n  cedar:\n    language: { name: cedar, constraint: \">=4.0.0\" }\n    engine: { name: permguard, constraint: \">=0.1.0\" }\npartitions:\n  app: { runtime: cedar, schema: false }\nprofiles:\n  default: { type: permguard.pdp.v1, partitions: [app] }\n").unwrap();
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
        ("GET".to_owned(), "/.well-known/server-configuration".to_owned()),
        (200, r#"{"product":"Permguard","version":"0.1.0"}"#.to_owned()),
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
