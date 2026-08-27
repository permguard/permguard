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
/// A plane reports an evaluation it could not perform as `context.reason_admin` with code `500`,
/// and refuses a request that is missing a field with a `4xx` naming the field. Both are "the
/// request could not be evaluated", which is what a case expecting an error is asking about.
#[test]
fn test_remote_carries_the_planes_refusals_into_the_expectation() {
    // An evaluation the plane could not perform.
    let dir = scratch("remote-error");
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
    for (what, body, ok) in [
        (
            "stopped at the first deny, as it must",
            r#"{"decision":false,"evaluations":[
                 {"decision":true,"request_id":"read"},{"decision":false,"request_id":"create"}]}"#,
            true,
        ),
        (
            "every answer a permit, so every one runs",
            r#"{"decision":true,"evaluations":[
                 {"decision":true,"request_id":"read"},{"decision":true,"request_id":"create"},
                 {"decision":true,"request_id":"purge"}]}"#,
            true,
        ),
        (
            "one permit offered as the whole batch",
            r#"{"decision":true,"evaluations":[{"decision":true,"request_id":"read"}]}"#,
            false,
        ),
        (
            "kept going past the deny that ends it",
            r#"{"decision":false,"evaluations":[
                 {"decision":false,"request_id":"read"},{"decision":true,"request_id":"create"},
                 {"decision":true,"request_id":"purge"}]}"#,
            false,
        ),
    ] {
        let dir = scratch("remote-stop-deny");
        stopping_workspace(&dir, "deny_on_first_deny");

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

    // `permit_on_first_permit`: the mirror image.
    for (what, body, ok) in [
        (
            "stopped at the first permit, as it must",
            r#"{"decision":false,"evaluations":[
                 {"decision":false,"request_id":"read"},{"decision":true,"request_id":"create"}]}"#,
            true,
        ),
        (
            "one deny offered as the whole batch",
            r#"{"decision":false,"evaluations":[{"decision":false,"request_id":"read"}]}"#,
            false,
        ),
        (
            "kept going past the permit that ends it",
            r#"{"decision":false,"evaluations":[
                 {"decision":true,"request_id":"read"},{"decision":false,"request_id":"create"},
                 {"decision":false,"request_id":"purge"}]}"#,
            false,
        ),
    ] {
        let dir = scratch("remote-stop-permit");
        stopping_workspace(&dir, "permit_on_first_permit");

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
fn stopping_workspace(dir: &Path, semantic: &str) {
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
    // The case asserts nothing about the outcome: what is under test is whether the answer is
    // accepted as an answer at all.
    std::fs::write(
        dir.join("tests/cases.yml"),
        "- name: three in one\n  request: ../requests/batch.json\n  expect: {}\n",
    )
    .expect("the cases are written");

    run(dir, &["init", "stop-cases"]);
}
