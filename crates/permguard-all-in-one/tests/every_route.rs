// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! Every REST route of every Plane, as the contracts state it, on a running all-in-one
//! (`2-security/8` Authorization): a route that names a credential refuses nobody `401` before it
//! reads anything, a body it cannot parse included; a token that does not verify is refused `401`
//! on every route, the open ones too; and the administrator is never refused for who it is. A
//! route added without authorizing, or one that reads its body before it knows the caller, fails
//! here. The Host API's routes have the same walk on both bindings in `permguard-server`.

#![allow(clippy::expect_used)]

use std::io::Read as _;
use std::process::{Child, Command};

use serde_json::{Value, json};

fn binary() -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_permguard-all-in-one"));
    for (name, _) in std::env::vars_os() {
        if name.to_string_lossy().starts_with("PERMGUARD_") {
            command.env_remove(name);
        }
    }
    command
}

/// The status and body of one request with curl, its extra arguments before the URL.
fn curl(method: &str, url: &str, extra: &[&str]) -> (u16, String) {
    let output = Command::new("curl")
        .args([
            "-sS",
            "--max-time",
            "10",
            "-X",
            method,
            "-w",
            "\n%{http_code}",
        ])
        .args(extra)
        .arg(url)
        .output()
        .expect("curl runs");
    let text = String::from_utf8_lossy(&output.stdout).into_owned();
    let (body, status) = text.rsplit_once('\n').unwrap_or(("", "0"));
    (status.trim().parse().unwrap_or(0), body.to_owned())
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .and_then(|listener| listener.local_addr())
        .map(|address| address.port())
        .expect("a free port")
}

/// Starts the runtime on `dir` and reads its log until it serves.
fn start(dir: &std::path::Path) -> (Child, String) {
    let mut child = binary()
        .arg(dir.join("config.yml"))
        .env("PERMGUARD_WORKING_DIR", dir)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("the runtime starts");
    let mut stdout = child.stdout.take().expect("stdout is piped");
    let mut seen = String::new();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
    let mut buffer = [0u8; 4096];
    while std::time::Instant::now() < deadline && !seen.contains("server.started") {
        match stdout.read(&mut buffer) {
            Ok(0) => break,
            Ok(read) => seen.push_str(&String::from_utf8_lossy(&buffer[..read])),
            Err(_) => break,
        }
    }
    (child, seen)
}

/// A body the schema accepts: every required field, the first enumerated value, a name.
fn body_of(document: &Value, schema: &Value, seed: usize) -> Value {
    let schema = match schema.get("$ref").and_then(Value::as_str) {
        Some(reference) => {
            let name = reference.rsplit('/').next().expect("a schema name");
            &document["components"]["schemas"][name]
        }
        None => schema,
    };
    let kinds: Vec<&str> = match &schema["type"] {
        Value::String(kind) => vec![kind.as_str()],
        Value::Array(kinds) => kinds.iter().filter_map(Value::as_str).collect(),
        _ => vec!["object"],
    };
    if kinds.contains(&"null") {
        return Value::Null;
    }
    if let Some(first) = schema["enum"].as_array().and_then(|values| values.first()) {
        return first.clone();
    }
    match kinds.first().copied().unwrap_or("object") {
        "string" => json!(format!("walk-{seed}")),
        "integer" | "number" => json!(0),
        "boolean" => json!(false),
        "array" => {
            if schema["minItems"].as_u64().unwrap_or(0) > 0 {
                json!([body_of(document, &schema["items"], seed)])
            } else {
                json!([])
            }
        }
        _ => {
            let mut object = serde_json::Map::new();
            for name in schema["required"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
            {
                object.insert(
                    name.to_owned(),
                    body_of(document, &schema["properties"][name], seed),
                );
            }
            Value::Object(object)
        }
    }
}

/// One route of a contract, made concrete: path parameters take their schema's first value or a
/// name, required query parameters a name; the body the request takes, when it takes one.
struct Route {
    method: String,
    path: String,
    plane: String,
    open: bool,
    /// The token endpoint proves a client by its key, never by a token.
    by_key: bool,
    content_type: Option<String>,
    body: Option<String>,
}

fn routes_of(document: &Value, seed: &mut usize) -> Vec<Route> {
    let mut routes = Vec::new();
    for (path, operations) in document["paths"].as_object().expect("paths") {
        for (method, operation) in operations.as_object().expect("operations") {
            if !["get", "post", "put", "patch", "delete"].contains(&method.as_str()) {
                continue;
            }
            let endpoint = &operation["x-permguard-endpoint"];
            let parameters = operation["parameters"]
                .as_array()
                .cloned()
                .unwrap_or_default();
            let mut concrete = path
                .split('/')
                .map(|segment| {
                    let Some(name) = segment.strip_prefix('{').and_then(|s| s.strip_suffix('}'))
                    else {
                        return segment.to_owned();
                    };
                    parameters
                        .iter()
                        .find(|parameter| parameter["name"] == name)
                        .and_then(|parameter| parameter["schema"]["enum"][0].as_str())
                        .map_or_else(|| "walk".to_owned(), str::to_owned)
                })
                .collect::<Vec<_>>()
                .join("/");
            let query: Vec<String> = parameters
                .iter()
                .filter(|parameter| parameter["in"] == "query" && parameter["required"] == true)
                .map(|parameter| format!("{}=walk", parameter["name"].as_str().expect("a name")))
                .collect();
            if !query.is_empty() {
                concrete = format!("{concrete}?{}", query.join("&"));
            }
            let content = operation["requestBody"]["content"]
                .as_object()
                .and_then(|content| content.iter().next());
            let (content_type, body) = match content {
                Some((kind, media)) if kind == "application/json" => {
                    *seed += 1;
                    (
                        Some(kind.clone()),
                        Some(body_of(document, &media["schema"], *seed).to_string()),
                    )
                }
                Some((kind, _)) => (Some(kind.clone()), None),
                None => (None, None),
            };
            routes.push(Route {
                method: method.to_uppercase(),
                path: concrete,
                plane: endpoint["plane"].as_str().unwrap_or_default().to_owned(),
                open: endpoint["credential"] == "no",
                by_key: endpoint["credential"] == "access key and secret key",
                content_type,
                body,
            });
        }
    }
    routes
}

#[test]
fn every_route_refuses_nobody_and_a_forged_token_and_admits_the_administrator() {
    let dir = std::env::temp_dir().join(format!("permguard-every-route-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("the scratch directory is created");
    let (authority, control, data, host) = (free_port(), free_port(), free_port(), free_port());
    std::fs::write(
        dir.join("config.yml"),
        format!(
            "development_mode: true\nautogenerate: true\nassurance:\n  profile: development\n\
             log:\n  level: info\n  format: json\n\
             experimental:\n  dogwood: {{ enabled: true }}\n\
             host:\n  addr: 127.0.0.1:{host}\n\
             runtime:\n  planes: [authority, control, data]\n\
             authority:\n  url: http://127.0.0.1:{authority}\n\
             authorityPlane:\n  public:\n    http: {{ addr: 127.0.0.1:{authority} }}\n\
             operations:\n\
             \x20 keys: {{ enabled: \"true\", publish_ahead: 5m, rotate_every: 1h, retain: 1d }}\n\
             \x20 secrets: {{ provider: directory, coordinator_root_ref: zone-root }}\n\
             \x20 audit: {{ pseudonym: {{ enabled: true, key_ref: audit-pseudonym, key_version: \"v1\" }} }}\n\
             controlPlane:\n  public:\n    http: {{ addr: 127.0.0.1:{control} }}\n\
             \x20 decisions: {{ enabled: \"true\" }}\n\
             \x20 events: {{ enabled: \"true\" }}\n\
             dataPlane:\n  public:\n    http: {{ addr: 127.0.0.1:{data} }}\n\
             \x20 mirrors: {{ enabled: \"true\", interval: 5s }}\n\
             \x20 decisions:\n    log: {{ enabled: \"true\" }}\n\
             \x20 events:\n    enabled: \"true\"\n    directory: data/events\n"
        ),
    )
    .expect("the config writes");
    let (mut child, seen) = start(&dir);
    let outcome = (|| {
        if !seen.contains("server.started") {
            return Err(format!("the runtime did not start: {seen}"));
        }
        let text = std::fs::read_to_string(dir.join("planes/authority/admin.key"))
            .map_err(|error| error.to_string())?;
        let field = |name: &str| {
            text.lines()
                .find_map(|line| line.strip_prefix(name).map(str::trim).map(str::to_owned))
                .ok_or(format!("no {name} in the key file"))
        };
        let (access_key, secret_key) = (field("access_key:")?, field("secret_key:")?);
        let issued = Command::new("curl")
            .args(["-sS", "--max-time", "10", "-u"])
            .arg(format!("{access_key}:{secret_key}"))
            .args(["--data", "grant_type=client_credentials"])
            .arg(format!("http://127.0.0.1:{authority}/authority/v1/token"))
            .output()
            .expect("curl runs");
        let issued = String::from_utf8_lossy(&issued.stdout).into_owned();
        let token = issued
            .split_once("\"access_token\":\"")
            .and_then(|(_, rest)| rest.split_once('"'))
            .map(|(token, _)| token.to_owned())
            .ok_or(format!("no token: {issued}"))?;
        let admin = format!("authorization: Bearer {token}");
        let listeners = [
            ("authority", format!("http://127.0.0.1:{authority}")),
            ("control", format!("http://127.0.0.1:{control}")),
            ("data", format!("http://127.0.0.1:{data}")),
            ("every surface", format!("http://127.0.0.1:{host}")),
        ];
        let contracts =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../contracts/openapi");
        let mut offences = Vec::new();
        let mut walked = 0;
        let mut seed = 0;
        for entry in std::fs::read_dir(&contracts).map_err(|error| error.to_string())? {
            let path = entry.map_err(|error| error.to_string())?.path();
            let document: Value =
                serde_json::from_slice(&std::fs::read(&path).map_err(|error| error.to_string())?)
                    .map_err(|error| format!("{}: {error}", path.display()))?;
            for route in routes_of(&document, &mut seed) {
                // The Host API has its own walk, on both bindings, in `permguard-server`.
                if route.plane == "host" {
                    continue;
                }
                let bases: Vec<&str> = listeners
                    .iter()
                    .filter(|(plane, _)| route.plane == "every surface" || *plane == route.plane)
                    .map(|(_, base)| base.as_str())
                    .collect();
                for base in bases {
                    walked += 1;
                    let url = format!("{base}{}", route.path);
                    let name = format!("{} {} on {base}", route.method, route.path);
                    let content_type = route
                        .content_type
                        .as_ref()
                        .map(|kind| format!("content-type: {kind}"));
                    let with = |extra: &[&str], body: Option<&str>| {
                        let mut args: Vec<&str> = extra.to_vec();
                        if let Some(content_type) = &content_type {
                            args.extend(["-H", content_type]);
                        }
                        if let Some(body) = body {
                            args.extend(["--data-binary", body]);
                        }
                        curl(&route.method, &url, &args)
                    };
                    let (nobody, _) = with(&[], route.body.as_deref());
                    let (forged, _) = with(
                        &["-H", "authorization: Bearer not.a.token"],
                        route.body.as_deref(),
                    );
                    let (administrator, answered) = with(&["-H", &admin], route.body.as_deref());
                    if forged != 401 {
                        offences.push(format!("{name}: a forged token answered {forged}"));
                    }
                    if route.open {
                        if matches!(nobody, 401 | 403) {
                            offences.push(format!("{name}: open, yet nobody answered {nobody}"));
                        }
                    } else {
                        if nobody != 401 {
                            offences.push(format!("{name}: nobody answered {nobody}"));
                        }
                        // Nothing is read before the caller is known: a body that does not parse
                        // is refused for who sent it, not for what it holds.
                        if route.content_type.is_some() {
                            let (unreadable, _) = with(&[], Some("{"));
                            if unreadable != 401 {
                                offences.push(format!(
                                    "{name}: nobody with an unreadable body answered {unreadable}"
                                ));
                            }
                        }
                    }
                    if !route.by_key && matches!(administrator, 401 | 403) {
                        offences.push(format!(
                            "{name}: the administrator answered {administrator} {answered}"
                        ));
                    }
                }
            }
        }
        Ok::<_, String>((walked, offences))
    })();
    let _ = child.kill();
    let _ = child.wait();
    let _ = std::fs::remove_dir_all(&dir);
    let (walked, offences) = outcome.unwrap_or_else(|reason| panic!("{reason}"));
    assert!(walked > 60, "only {walked} routes were walked");
    assert!(
        offences.is_empty(),
        "{} of {walked}:\n{}",
        offences.len(),
        offences.join("\n")
    );
}
