// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! Transport parity on a running all-in-one (owner decision of 2026-11-15): a deployment serves
//! HTTP alone, gRPC alone, or both, and a client finds and reads every plane over whichever it
//! speaks.
//!
//! The process registry is REST on the Server Host listener by contract, beside health and
//! metrics. It names each plane's own document when the plane serves HTTP and its `grpc_endpoint`
//! when it serves gRPC; from there every document of every plane is read through the client
//! library's `documents` facade: the plane's document, its streams, its keys, the status lists,
//! and every interface it publishes. With both transports served, the two answers are the same
//! JSON.

#![allow(clippy::expect_used)]

use std::io::Read as _;
use std::process::{Child, Command};

use permguard_control_client::documents::{self, Interface, Plane};
use permguard_control_client::narrate::Silent;
use permguard_control_client::tls::TlsOptions;
use serde_json::Value;

fn binary() -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_permguard-all-in-one"));
    for (name, _) in std::env::vars_os() {
        if name.to_string_lossy().starts_with("PERMGUARD_") {
            command.env_remove(name);
        }
    }
    command
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .and_then(|listener| listener.local_addr())
        .map(|address| address.port())
        .expect("a free port")
}

/// A running all-in-one, stopped and its directory removed when dropped.
struct Running {
    child: Child,
    dir: std::path::PathBuf,
    host: u16,
}

impl Drop for Running {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// Which transports every plane serves.
#[derive(Clone, Copy, Debug)]
enum Served {
    Both,
    HttpOnly,
    GrpcOnly,
}

/// Starts the runtime with every plane serving `served`, and reads its log until it serves.
fn start(tag: &str, served: Served) -> Running {
    let dir =
        std::env::temp_dir().join(format!("permguard-transport-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("the scratch directory is created");
    let (authority, control, data, host) = (free_port(), free_port(), free_port(), free_port());
    let public = |port: u16| match served {
        Served::Both => format!(
            "http: {{ enabled: true, addr: 127.0.0.1:{port} }}\n    grpc: {{ enabled: true, addr: 127.0.0.1:{port} }}"
        ),
        Served::HttpOnly => format!(
            "http: {{ enabled: true, addr: 127.0.0.1:{port} }}\n    grpc: {{ enabled: false }}"
        ),
        // Over TLS, as a deployment serving gRPC alone does: a token travels only over verified TLS.
        Served::GrpcOnly => format!(
            "http: {{ enabled: false }}\n    grpc: {{ enabled: true, addr: 127.0.0.1:{port}, tls: {{ cert: tls/server.pem, key: tls/server.key }} }}"
        ),
    };
    // The issuer every token names: a name, the same whichever transport serves the Authority
    // Plane; in one process its keys and lists are handed over in memory, never fetched.
    let authority_url = format!("http://127.0.0.1:{authority}");
    // The Host listener over TLS names the material `autogenerate` writes, the authority and the
    // server's certificate, which the planes' gRPC listeners then serve with.
    let admin = match served {
        Served::GrpcOnly => format!(
            "admin:\n  addr: 127.0.0.1:{}\n  tls: {{ cert: tls/server.pem, key: tls/server.key }}\n",
            free_port()
        ),
        Served::Both | Served::HttpOnly => String::new(),
    };
    std::fs::write(
        dir.join("config.yml"),
        format!(
            "development_mode: true\nautogenerate: true\nassurance:\n  profile: development\n\
             log:\n  level: info\n  format: json\n\
             experimental:\n  dogwood: {{ enabled: true }}\n\
             host:\n  addr: 127.0.0.1:{host}\n\
             {admin}\
             runtime:\n  planes: [authority, control, data]\n\
             authority:\n  url: {authority_url}\n\
             authorityPlane:\n  public:\n    {}\n\
             operations:\n\
             \x20 keys: {{ enabled: \"true\", publish_ahead: 5m, rotate_every: 1h, retain: 1d }}\n\
             \x20 secrets: {{ provider: directory, coordinator_root_ref: zone-root }}\n\
             \x20 audit: {{ pseudonym: {{ enabled: true, key_ref: audit-pseudonym, key_version: \"v1\" }} }}\n\
             controlPlane:\n  public:\n    {}\n\
             \x20 decisions: {{ enabled: \"true\" }}\n\
             \x20 events: {{ enabled: \"true\" }}\n\
             dataPlane:\n  public:\n    {}\n\
             \x20 decisions:\n    log: {{ enabled: \"true\" }}\n\
             \x20 events:\n    enabled: \"true\"\n    directory: data/events\n",
            public(authority),
            public(control),
            public(data),
        ),
    )
    .expect("the config writes");
    let mut child = binary()
        .arg(dir.join("config.yml"))
        .env("PERMGUARD_WORKING_DIR", &dir)
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
    // Drained from here on, so a full pipe never blocks the runtime.
    std::thread::spawn(move || std::io::copy(&mut stdout, &mut std::io::sink()));
    assert!(
        seen.contains("server.started"),
        "the runtime did not start ({served:?}): {seen}"
    );
    Running { child, dir, host }
}

/// The process registry: REST on the Server Host listener.
fn registry(running: &Running) -> Value {
    let output = Command::new("curl")
        .args(["-sS", "--max-time", "10"])
        .arg(format!(
            "http://127.0.0.1:{}/.well-known/server-configuration",
            running.host
        ))
        .output()
        .expect("curl runs");
    serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
        panic!(
            "the registry is not JSON: {error}: {}",
            String::from_utf8_lossy(&output.stdout)
        )
    })
}

/// The planes of the registry: each one's REST base and gRPC URL, when it names them.
fn planes(registry: &Value) -> Vec<(Plane, Option<String>, Option<String>)> {
    let mut planes: Vec<_> = registry["planes"]
        .as_object()
        .expect("the registry names planes")
        .iter()
        .map(|(name, link)| {
            let plane = Plane::of_name(name).unwrap_or_else(|| panic!("`{name}` is not a plane"));
            let rest = link["server_configuration"].as_str().map(|url| {
                url.strip_suffix("/.well-known/server-configuration")
                    .expect("a plane's document is at its well-known")
                    .to_owned()
            });
            // The registry names the gRPC endpoint by the scheme its TLS decides.
            let grpc = link["grpc_endpoint"].as_str().map(|url| {
                url.replacen("https://", "grpcs://", 1)
                    .replacen("http://", "grpc://", 1)
            });
            (plane, rest, grpc)
        })
        .collect();
    planes.sort_by_key(|(plane, ..)| plane.name());
    assert_eq!(planes.len(), 3, "{registry}");
    planes
}

/// Every document `plane` publishes, read at `url` under `tls`, by name.
fn every_document(plane: Plane, url: &str, tls: &TlsOptions) -> Vec<(String, Value)> {
    let read = documents::client(url, plane, tls, Box::new(Silent))
        .unwrap_or_else(|error| panic!("{url}: {error}"));
    let answer =
        |what: &str, answered: Result<Value, permguard_control_client::catalog::Failure>| {
            answered.unwrap_or_else(|failure| {
                panic!("{} `{what}` at {url}: {}", plane.name(), failure.detail)
            })
        };
    let configuration = answer("configuration", read.configuration());
    let mut held = vec![("keys".to_owned(), answer("keys", read.keys()))];
    // A plane's health moves with time: its liveness, readiness, phase and components compared,
    // never the instants a component last succeeded.
    let health = answer("health", read.health());
    held.push((
        "health".to_owned(),
        serde_json::json!({
            "live": health["live"],
            "ready": health["ready"],
            "state": health["state"],
            "components": health["components"]
                .as_array()
                .into_iter()
                .flatten()
                .map(|component| (component["component"].clone(), component["kind"].clone(), component["required"].clone()))
                .map(|(component, kind, required)| serde_json::json!([component, kind, required]))
                .collect::<Vec<_>>(),
        }),
    ));
    match plane {
        Plane::Authority => {
            held.push((
                "status_lists".to_owned(),
                answer("status lists", read.status_lists()),
            ));
        }
        Plane::Control | Plane::Data => {
            held.push(("streams".to_owned(), answer("streams", read.streams())));
        }
    }
    let interfaces: Vec<Interface> = configuration["interfaces"]
        .as_object()
        .into_iter()
        .flatten()
        .filter_map(|(id, _)| Interface::of_id(id))
        .collect();
    if plane != Plane::Authority {
        assert!(
            !interfaces.is_empty(),
            "{} publishes interfaces",
            plane.name()
        );
    }
    for interface in interfaces {
        held.push((
            interface.id().to_owned(),
            answer(interface.id(), read.interface(interface)),
        ));
    }
    held.push(("configuration".to_owned(), configuration));
    held
}

#[test]
fn every_document_of_every_plane_is_the_same_over_rest_and_grpc() {
    let running = start("both", Served::Both);
    for (plane, rest, grpc) in planes(&registry(&running)) {
        let rest = rest.unwrap_or_else(|| panic!("{} names its document", plane.name()));
        let grpc = grpc.unwrap_or_else(|| panic!("{} names its gRPC endpoint", plane.name()));
        let over_rest = every_document(plane, &rest, &TlsOptions::default());
        let over_grpc = every_document(plane, &grpc, &TlsOptions::default());
        assert_eq!(
            over_rest.iter().map(|(name, _)| name).collect::<Vec<_>>(),
            over_grpc.iter().map(|(name, _)| name).collect::<Vec<_>>(),
            "{}: the same documents",
            plane.name()
        );
        for ((name, rest), (_, grpc)) in over_rest.iter().zip(&over_grpc) {
            assert_eq!(
                rest,
                grpc,
                "{} `{name}`: the same JSON both ways",
                plane.name()
            );
        }
    }
}

#[test]
fn with_http_off_every_plane_is_found_and_read_over_grpc() {
    let running = start("grpc-only", Served::GrpcOnly);
    // The authority the runtime generated its certificate under.
    let verified = TlsOptions {
        ca_file: Some(running.dir.join("tls/ca.pem")),
        ..TlsOptions::default()
    };
    let mut endpoints = std::collections::BTreeMap::new();
    for (plane, rest, grpc) in planes(&registry(&running)) {
        assert!(rest.is_none(), "{} serves no HTTP document", plane.name());
        let grpc = grpc.unwrap_or_else(|| panic!("{} names its gRPC endpoint", plane.name()));
        assert!(grpc.starts_with("grpcs://"), "{grpc}");
        let read = every_document(plane, &grpc, &verified);
        assert!(read.len() >= 3, "{}: {read:?}", plane.name());
        endpoints.insert(plane.name(), grpc);
    }
    // A token issued over gRPC, with the administrator's key, admits an operation over gRPC: the
    // whole chain with HTTP off, from the Authority Plane to a Plane that verifies its tokens.
    let text = std::fs::read_to_string(running.dir.join("planes/authority/admin.key"))
        .expect("the administrator's key is written");
    let field = |name: &str| {
        text.lines()
            .find_map(|line| line.strip_prefix(name).map(str::trim).map(str::to_owned))
            .unwrap_or_else(|| panic!("no {name} in the key file"))
    };
    let authority = permguard_control_client::authority::client(
        &endpoints["authority-plane"],
        &verified,
        Box::new(Silent),
    )
    .expect("the Authority Plane's client");
    let token = authority
        .issue_token(&permguard_control_client::authority::TokenAsk {
            access_key: field("access_key:"),
            secret_key: zeroize::Zeroizing::new(field("secret_key:")),
            scope: None,
            lifetime: None,
        })
        .unwrap_or_else(|failure| panic!("a token over gRPC: {}", failure.detail))
        .access_token;
    let tls = TlsOptions {
        token: Some(permguard_control_client::tls::Credential::new(
            token.into_bytes(),
        )),
        ..verified.clone()
    };
    let catalog = permguard_control_client::catalog::client(
        &endpoints["control-plane"],
        &tls,
        Box::new(Silent),
    )
    .expect("the catalog's client");
    let zone = catalog
        .create_zone("over-grpc")
        .unwrap_or_else(|failure| panic!("a zone created over gRPC: {}", failure.detail));
    let zones = catalog
        .list_zones(None, None)
        .unwrap_or_else(|failure| panic!("the zones over gRPC: {}", failure.detail));
    assert!(zones.iter().any(|listed| listed.id == zone.id), "{zones:?}");
}

#[test]
fn with_grpc_off_every_plane_is_found_and_read_over_rest() {
    let running = start("http-only", Served::HttpOnly);
    for (plane, rest, grpc) in planes(&registry(&running)) {
        assert!(grpc.is_none(), "{} names no gRPC endpoint", plane.name());
        let rest = rest.unwrap_or_else(|| panic!("{} names its document", plane.name()));
        let read = every_document(plane, &rest, &TlsOptions::default());
        assert!(read.len() >= 3, "{}: {read:?}", plane.name());
    }
}
