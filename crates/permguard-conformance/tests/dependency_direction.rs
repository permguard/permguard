// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The dependency direction of the composition (`1-architecture-server.md`): a Plane depends on the
//! Host, never the reverse. The Host, and every workspace crate it reaches, reaches no concrete Plane
//! and no binary that composes one, through any path of the resolved graph, normal or build.
//! `task check:core-deps` and `task check:seams` hold the narrower rules; this one reads the
//! graph cargo itself resolved, so a Plane reached transitively is caught too.

#![allow(clippy::expect_used)]

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::process::Command;

/// The crates a Plane is, or that compose one.
const ABOVE_THE_HOST: &[&str] = &[
    "permguard-authority-plane",
    "permguard-authority-plane-server",
    "permguard-control-plane",
    "permguard-control-plane-server",
    "permguard-data-plane",
    "permguard-data-plane-server",
    "permguard-all-in-one",
    "permguard-cli",
];

/// Every workspace package name, and the names it reaches through normal and build dependencies.
fn reached() -> BTreeMap<String, BTreeSet<String>> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_owned());
    let output = Command::new(cargo)
        // Every feature: a Plane reached only through one that is off by default still counts.
        // Not offline: with every feature, cargo reads the manifests of dependencies for other
        // platforms too, which a runner's cache may not hold; the lockfile still pins them all.
        .args([
            "metadata",
            "--format-version",
            "1",
            "--all-features",
            "--locked",
        ])
        .current_dir(&root)
        .output()
        .expect("cargo metadata runs");
    assert!(
        output.status.success(),
        "cargo metadata: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let metadata: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("cargo metadata is JSON");
    let names: BTreeMap<&str, &str> = metadata["packages"]
        .as_array()
        .expect("packages")
        .iter()
        .map(|package| {
            (
                package["id"].as_str().expect("an id"),
                package["name"].as_str().expect("a name"),
            )
        })
        .collect();
    // Each node's direct edges, dev-dependencies left out: a test may compose anything.
    let edges: BTreeMap<&str, Vec<&str>> = metadata["resolve"]["nodes"]
        .as_array()
        .expect("the resolved graph")
        .iter()
        .map(|node| {
            let to = node["deps"]
                .as_array()
                .expect("deps")
                .iter()
                .filter(|dep| {
                    dep["dep_kinds"]
                        .as_array()
                        .expect("dep kinds")
                        .iter()
                        .any(|kind| kind["kind"].as_str() != Some("dev"))
                })
                .map(|dep| dep["pkg"].as_str().expect("a package id"))
                .collect();
            (node["id"].as_str().expect("a node id"), to)
        })
        .collect();
    let mut closures = BTreeMap::new();
    for member in metadata["workspace_members"]
        .as_array()
        .expect("members")
        .iter()
        .map(|member| member.as_str().expect("a member id"))
    {
        let mut seen = BTreeSet::new();
        let mut pending = vec![member];
        while let Some(id) = pending.pop() {
            for next in edges.get(id).into_iter().flatten() {
                if seen.insert(*next) {
                    pending.push(next);
                }
            }
        }
        closures.insert(
            names[member].to_owned(),
            seen.into_iter().map(|id| names[id].to_owned()).collect(),
        );
    }
    closures
}

#[test]
fn the_host_and_the_crates_beneath_it_reach_no_plane() {
    let closures = reached();
    // Beneath the Host: itself and every workspace crate it reaches, whatever they are named.
    let mut beneath: Vec<&str> = closures["permguard-host"]
        .iter()
        .filter(|name| closures.contains_key(name.as_str()))
        .map(String::as_str)
        .collect();
    beneath.push("permguard-host");
    for shared in ["permguard-core", "permguard-objects"] {
        assert!(beneath.contains(&shared), "{shared} is beneath the Host");
    }
    let mut problems = Vec::new();
    for crate_name in &beneath {
        for plane in ABOVE_THE_HOST {
            if closures[*crate_name].contains(*plane) {
                problems.push(format!("{crate_name} reaches {plane}"));
            }
        }
    }
    assert!(
        problems.is_empty(),
        "a Plane depends on the Host, never the reverse:\n  {}",
        problems.join("\n  ")
    );
    // The check reads a real graph: the Planes do reach the Host.
    for plane in [
        "permguard-authority-plane",
        "permguard-control-plane",
        "permguard-data-plane",
    ] {
        assert!(
            closures[plane].contains("permguard-host"),
            "{plane} composes on the Host"
        );
    }
}

/// The network and server stack: what only a server adapter, a listener or a network client links
/// (`11-refactoring/1-dependencies.md`, Target dependency layers).
const SERVER_STACK: &[&str] = &[
    "permguard-server",
    "permguard-transport",
    "permguard-telemetry",
    "axum",
    "tonic",
    "hyper",
    "tower-http",
    "opentelemetry",
];

/// What each layer may not reach, through any normal or build dependency, with every feature on.
/// A phase of the crate boundaries refactoring adds its rows when its split lands, so a boundary
/// once drawn cannot be crossed again unnoticed.
const LAYERS: &[(&str, &[&str])] = &[
    // The headless protocol, Host and evidence crates: no listener, no network stack.
    ("permguard-core", SERVER_STACK),
    ("permguard-objects", SERVER_STACK),
    ("permguard-notp", SERVER_STACK),
    ("permguard-host", SERVER_STACK),
    ("permguard-std", SERVER_STACK),
    ("permguard-stream", SERVER_STACK),
    ("permguard-decisions", SERVER_STACK),
    ("permguard-events", SERVER_STACK),
    // The policy languages validate and evaluate; they serve nothing and call nobody (RD-6): the
    // contracts link no engine, and each engine links no other and never the catalogue that
    // carries it.
    ("permguard-languages", SERVER_STACK),
    ("permguard-language-core", LANGUAGE_CORE),
    // The decision point's evaluating half links no engine either: the engines link it.
    ("permguard-pdp-core", LANGUAGE_CORE),
    ("permguard-language-core", &["permguard-pdp-core"]),
    ("permguard-language-cedar", CEDAR_ENGINE),
    ("permguard-language-rego", REGO_ENGINE),
    ("permguard-language-dogwood", DOGWOOD_ENGINE),
    // A Plane's domain serves nothing (RD-1): its routes, module and binary are its server
    // package's.
    ("permguard-authority-plane", SERVER_STACK),
    // The Data Plane's domain listens nowhere and composes no server (RD-2), and links no network
    // client either (RD-12): its mirror is filled over the sessions of the tasks its Host serves.
    ("permguard-data-plane", SERVER_STACK),
    ("permguard-data-plane", NO_CLIENT),
    // The verified mirror opens no connection: who answers its pull is handed to it.
    ("permguard-mirror", SERVER_STACK),
    ("permguard-mirror", NO_CLIENT),
    ("permguard-mirror", NO_LANGUAGE),
    // Nor does the synchronization of the mirrors, which is client-neutral, and decides nothing:
    // what decides against a mirror hears of an advance through a trait.
    ("permguard-sync", SERVER_STACK),
    ("permguard-sync", NO_CLIENT),
    ("permguard-sync", NO_LANGUAGE),
    (
        "permguard-sync",
        &["permguard-pdp-core", "permguard-language-core"],
    ),
    // The Control Plane's domain serves nothing and composes no other Plane (RD-3): the Authority
    // Plane is registered beside it by its server package.
    ("permguard-control-plane", CONTROL_PLANE_DOMAIN),
    // Generated contracts have one owner, and a domain selects none of them (RD-9): only an
    // adapter, a client's or a server's, speaks a wire.
    ("permguard-host", &["permguard-contracts"]),
    ("permguard-authority-plane", &["permguard-contracts"]),
    ("permguard-control-plane", &["permguard-contracts"]),
    // Offline volume administration has no server in it, and the command line links it and the
    // domain libraries: no server composition, listener, or telemetry (RD-13). Permguard Admin
    // links the command line, so its core follows.
    ("permguard-offline", SERVER_SIDE),
    ("permguard-cli", SERVER_SIDE),
    // The canonical primitives are nobody's runtime (RD-16): the language contracts compute their
    // digests and read the protocol's instant with them, and link no evidence store or stream.
    ("permguard-canonical", EVIDENCE_RUNTIME),
    (
        "permguard-canonical",
        &["permguard-core", "permguard-host", "permguard-objects"],
    ),
    ("permguard-language-core", EVIDENCE_RUNTIME),
    ("permguard-pdp-core", EVIDENCE_RUNTIME),
    // A client speaks the request model and compiles no policy language (RD-6).
    ("permguard-client", NO_LANGUAGE),
];

/// What the language contracts and the decision point's evaluating half may not reach: the server
/// stack, any engine package, the catalogue, any engine, and the JSON Schema validator only Rego
/// admits its input through.
const LANGUAGE_CORE: &[&str] = &[
    "permguard-server",
    "permguard-transport",
    "permguard-telemetry",
    "axum",
    "tonic",
    "hyper",
    "tower-http",
    "opentelemetry",
    "permguard-languages",
    "permguard-language-cedar",
    "permguard-language-rego",
    "permguard-language-dogwood",
    "cedar-policy",
    "cedar-policy-core",
    "regorus",
    "jsonschema",
    "dogwood-language",
];

/// What the Cedar engine package may not reach: the server stack, the other engines, the catalogue.
const CEDAR_ENGINE: &[&str] = &[
    "permguard-server",
    "permguard-transport",
    "permguard-telemetry",
    "axum",
    "tonic",
    "hyper",
    "tower-http",
    "opentelemetry",
    "permguard-languages",
    "permguard-language-rego",
    "permguard-language-dogwood",
    "regorus",
    "jsonschema",
    "dogwood-language",
];

/// What the Rego engine package may not reach: the server stack, the other engine packages and
/// engines, the catalogue.
const REGO_ENGINE: &[&str] = &[
    "permguard-server",
    "permguard-transport",
    "permguard-telemetry",
    "axum",
    "tonic",
    "hyper",
    "tower-http",
    "opentelemetry",
    "permguard-languages",
    "permguard-language-cedar",
    "permguard-language-dogwood",
    "cedar-policy",
    "cedar-policy-core",
    "dogwood-language",
];

/// What the Dogwood engine package may not reach: the server stack, the other engine packages, the
/// catalogue, and the Rego engine. Cedar is Dogwood's own: it lowers to it.
const DOGWOOD_ENGINE: &[&str] = &[
    "permguard-server",
    "permguard-transport",
    "permguard-telemetry",
    "axum",
    "tonic",
    "hyper",
    "tower-http",
    "opentelemetry",
    "permguard-languages",
    "permguard-language-cedar",
    "permguard-language-rego",
    "regorus",
    "jsonschema",
];

/// The evidence packages and the stream engine: what keeps records, which a package that only
/// computes over canonical bytes never links.
const EVIDENCE_RUNTIME: &[&str] = &[
    "permguard-decisions",
    "permguard-events",
    "permguard-stream",
];

/// What only a served process links: the server composition, the listeners, the telemetry
/// endpoints and exporters, and the three server adapters.
const SERVER_SIDE: &[&str] = &[
    "permguard-server",
    "permguard-transport",
    "permguard-telemetry",
    "permguard-authority-plane-server",
    "permguard-control-plane-server",
    "permguard-data-plane-server",
    "permguard-all-in-one",
    "tower-http",
    "opentelemetry",
];

/// What a package with no network client may not reach: the client library, the generated
/// contracts, and the rustls stack only a client or a listener links.
const NO_CLIENT: &[&str] = &["permguard-client", "permguard-contracts", "rustls"];

/// What a package that only speaks the request model may not reach: any policy language.
const NO_LANGUAGE: &[&str] = &[
    "permguard-languages",
    "permguard-language-cedar",
    "permguard-language-rego",
    "permguard-language-dogwood",
    "cedar-policy",
    "cedar-policy-core",
    "regorus",
    "jsonschema",
    "dogwood-language",
];

/// What the Control Plane's domain may not reach: the server stack, and the Authority Plane its
/// binary registers beside it.
const CONTROL_PLANE_DOMAIN: &[&str] = &[
    "permguard-server",
    "permguard-transport",
    "permguard-telemetry",
    "axum",
    "tonic",
    "hyper",
    "tower-http",
    "opentelemetry",
    "permguard-authority-plane",
    "permguard-authority-plane-server",
];

#[test]
fn each_layer_reaches_only_what_it_allows() {
    let closures = reached();
    let mut problems = Vec::new();
    for (package, forbidden) in LAYERS {
        let reached = closures
            .get(*package)
            .unwrap_or_else(|| panic!("{package} is a workspace member"));
        for name in *forbidden {
            if reached.contains(*name) {
                problems.push(format!("{package} reaches {name}"));
            }
        }
    }
    assert!(
        problems.is_empty(),
        "a layer reaches what it may not (11-refactoring, Target dependency layers):\n  {}",
        problems.join("\n  ")
    );
    // The check reads a real graph: a server composition does reach the stack it forbids.
    for name in SERVER_STACK {
        assert!(
            closures["permguard-all-in-one"].contains(*name),
            "the all-in-one reaches {name}"
        );
    }
}

/// What a build of `package` with only `features` links, through normal and build dependencies:
/// the packages `cargo tree` resolves for it, built by itself, by name.
fn carried_with(package: &str, features: &str) -> BTreeSet<String> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_owned());
    let output = Command::new(cargo)
        .args([
            "tree",
            "--locked",
            "--package",
            package,
            "--no-default-features",
            "--features",
            features,
            "--edges",
            "normal,build",
            "--prefix",
            "none",
            "--format",
            "{lib}",
        ])
        .current_dir(&root)
        .output()
        .expect("cargo tree runs");
    assert!(
        output.status.success(),
        "cargo tree: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(|line| line.trim().replace('_', "-"))
        .filter(|name| !name.is_empty())
        .collect()
}

/// A language is a feature of the catalogue (RD-7): a build that names one links that engine and no
/// other, Cedar excepted for Dogwood, which lowers to it. Evaluating is a feature too (RD-6): a
/// build that only validates links no decision point, whichever language it carries, and one that
/// evaluates does.
#[test]
fn a_build_links_only_the_engines_it_carries() {
    let mut problems = Vec::new();
    for (features, carried, absent) in [
        (
            "cedar",
            &["permguard-language-cedar", "cedar-policy"][..],
            &[
                "permguard-language-rego",
                "permguard-language-dogwood",
                "regorus",
                "jsonschema",
                "dogwood-language",
                "permguard-pdp-core",
            ][..],
        ),
        (
            "rego",
            &["permguard-language-rego", "regorus", "jsonschema"][..],
            &[
                "permguard-language-cedar",
                "permguard-language-dogwood",
                "cedar-policy",
                "cedar-policy-core",
                "dogwood-language",
                "permguard-pdp-core",
            ][..],
        ),
        (
            "cedar,rego,evaluate",
            &["permguard-pdp-core", "regorus", "cedar-policy"][..],
            &["permguard-language-dogwood", "dogwood-language"][..],
        ),
        (
            "dogwood",
            &["permguard-language-dogwood", "dogwood-language"][..],
            &[
                "permguard-language-cedar",
                "permguard-language-rego",
                "regorus",
                "jsonschema",
                "permguard-pdp-core",
            ][..],
        ),
        (
            "dogwood,evaluate",
            &["permguard-language-dogwood", "permguard-pdp-core"][..],
            &[
                "permguard-language-cedar",
                "permguard-language-rego",
                "regorus",
            ][..],
        ),
    ] {
        let linked = carried_with("permguard-languages", features);
        for name in carried {
            if !linked.contains(*name) {
                problems.push(format!("a `{features}` build does not link {name}"));
            }
        }
        for name in absent {
            if linked.contains(*name) {
                problems.push(format!("a `{features}` build links {name}"));
            }
        }
    }
    assert!(
        problems.is_empty(),
        "a build links exactly the engines it carries:\n  {}",
        problems.join("\n  ")
    );
}

/// The features `package`'s own build resolves for each workspace package it links, by name: what
/// `cargo tree` resolves when that package alone is built, as its release is.
fn features_of(package: &str) -> BTreeMap<String, BTreeSet<String>> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_owned());
    let output = Command::new(cargo)
        .args([
            "tree",
            "--locked",
            "--package",
            package,
            "--edges",
            "normal,build",
            "--prefix",
            "none",
            "--format",
            "{p}|{f}",
        ])
        .current_dir(&root)
        .output()
        .expect("cargo tree runs");
    assert!(
        output.status.success(),
        "cargo tree: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let mut features: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for line in String::from_utf8_lossy(&output.stdout).lines() {
        let Some((package, enabled)) = line.split_once('|') else {
            continue;
        };
        let name = package.split(' ').next().unwrap_or_default().to_owned();
        let enabled = enabled.trim().trim_end_matches("(*)").trim();
        features.entry(name).or_default().extend(
            enabled
                .split(',')
                .filter(|feature| !feature.is_empty())
                .map(str::to_owned),
        );
    }
    features
}

/// The Control Plane validates what a push carries and evaluates nothing (RD-6): its own build, the
/// domain's and the server's, carries every language and neither the decision point's evaluating
/// half (`permguard-pdp-core`) nor the `evaluate` feature that brings it, the routing and the
/// supervised worker. The Data Plane's build carries both.
#[test]
fn the_control_plane_validates_without_evaluating() {
    let control = features_of("permguard-control-plane-server");
    let data = features_of("permguard-data-plane-server");
    let mut problems = Vec::new();
    for package in ["permguard-control-plane", "permguard-control-plane-server"] {
        if features_of(package).contains_key("permguard-pdp-core") {
            problems.push(format!("{package} links permguard-pdp-core"));
        }
    }
    if !data.contains_key("permguard-pdp-core") {
        problems.push("the Data Plane does not link permguard-pdp-core".to_owned());
    }
    for package in [
        "permguard-languages",
        "permguard-language-cedar",
        "permguard-language-dogwood",
        "permguard-language-rego",
    ] {
        match control.get(package) {
            None => problems.push(format!("the Control Plane does not link {package}")),
            Some(enabled) if enabled.contains("evaluate") => {
                problems.push(format!(
                    "the Control Plane builds {package} with `evaluate`"
                ));
            }
            Some(_) => {}
        }
        if !data
            .get(package)
            .is_some_and(|enabled| enabled.contains("evaluate"))
        {
            problems.push(format!(
                "the Data Plane builds {package} without `evaluate`"
            ));
        }
    }
    for language in ["cedar", "dogwood", "rego"] {
        if !control
            .get("permguard-languages")
            .is_some_and(|enabled| enabled.contains(language))
        {
            problems.push(format!("the Control Plane does not carry {language}"));
        }
    }
    assert!(
        problems.is_empty(),
        "the Control Plane validates and the Data Plane evaluates:\n  {}",
        problems.join("\n  ")
    );
}

/// The Host's runtime is headless (RD-15), its composition included: built by itself it links no
/// listener, no network client, no generated contract, no TLS stack and no telemetry exporter.
/// What reaches a network is an adapter a build composes: a server's build selects the KMS custody
/// of `permguard-offline`, which the runtime's own build leaves out and refuses by name.
#[test]
fn the_runtime_is_headless_and_a_server_composes_its_adapters() {
    let runtime = carried_with("permguard-runtime", "");
    let mut problems = Vec::new();
    for name in SERVER_STACK.iter().copied().chain([
        "permguard-client",
        "permguard-contracts",
        "rustls",
        "tokio-rustls",
        "hyper-util",
    ]) {
        if runtime.contains(name) {
            problems.push(format!("permguard-runtime, built by itself, links {name}"));
        }
    }
    for name in ["permguard-host", "permguard-stream", "permguard-offline"] {
        if !runtime.contains(name) {
            problems.push(format!("permguard-runtime does not link {name}"));
        }
    }
    if features_of("permguard-runtime")
        .get("permguard-offline")
        .is_some_and(|enabled| enabled.contains("kms") || enabled.contains("pkcs11"))
    {
        problems.push("permguard-runtime selects a remote custody".to_owned());
    }
    if !features_of("permguard-server")
        .get("permguard-offline")
        .is_some_and(|enabled| enabled.contains("kms"))
    {
        problems.push("permguard-server does not compose the KMS custody".to_owned());
    }
    assert!(
        problems.is_empty(),
        "the runtime is headless and a server composes its adapters:\n  {}",
        problems.join("\n  ")
    );
}

/// A decision record and an event record are a normative model first (RD-14): built with no
/// feature, each package links no Host stream engine, which is what a verifier links; the durable
/// storage and the stream registration are features that bring it. The Control Plane's domain
/// registers the two streams and keeps what it receives in its own store, so its build takes the
/// registration and never a producer's spool or journal.
#[test]
fn an_evidence_model_links_no_stream_runtime_until_a_feature_asks() {
    let mut problems = Vec::new();
    for package in ["permguard-decisions", "permguard-events"] {
        if carried_with(package, "").contains("permguard-stream") {
            problems.push(format!(
                "{package}, the model alone, links permguard-stream"
            ));
        }
        for feature in ["storage", "stream"] {
            if !carried_with(package, feature).contains("permguard-stream") {
                problems.push(format!(
                    "{package} with `{feature}` does not link permguard-stream"
                ));
            }
        }
    }
    let control = features_of("permguard-control-plane");
    for package in ["permguard-decisions", "permguard-events"] {
        match control.get(package) {
            None => problems.push(format!("the Control Plane does not link {package}")),
            Some(enabled) => {
                if enabled.contains("storage") {
                    problems.push(format!("the Control Plane builds {package} with `storage`"));
                }
                if !enabled.contains("stream") {
                    problems.push(format!(
                        "the Control Plane builds {package} without `stream`"
                    ));
                }
            }
        }
    }
    assert!(
        problems.is_empty(),
        "an evidence model is selectable alone:
  {}",
        problems.join("\n  ")
    );
}

/// The embedded Data Plane carries the languages its application selects and no other, and none by
/// default (`11-refactoring/1-dependencies.md`, Feature and profile model): built by itself with
/// one language's feature, it links that engine, the decision point, and neither another engine
/// nor a server, a listener or a telemetry exporter.
#[test]
fn an_embedded_data_plane_links_only_the_languages_it_selects() {
    // What only a server or a network client links, and the default implementations an
    // application injects its own of.
    const NEVER: &[&str] = &[
        "permguard-server",
        "permguard-transport",
        "permguard-telemetry",
        "permguard-std",
        "permguard-client",
        "permguard-contracts",
        "axum",
        "tonic",
        "hyper",
        "tower-http",
        "opentelemetry",
    ];
    let mut problems = Vec::new();
    for (features, carried, absent) in [
        (
            "",
            &["permguard-language-core", "permguard-pdp-core"][..],
            &[
                "permguard-language-cedar",
                "permguard-language-rego",
                "permguard-language-dogwood",
                "cedar-policy",
                "regorus",
                "dogwood-language",
            ][..],
        ),
        (
            "cedar",
            &[
                "permguard-language-cedar",
                "cedar-policy",
                "permguard-pdp-core",
            ][..],
            &[
                "permguard-language-rego",
                "permguard-language-dogwood",
                "regorus",
                "jsonschema",
                "dogwood-language",
            ][..],
        ),
        (
            "rego",
            &["permguard-language-rego", "regorus", "permguard-pdp-core"][..],
            &[
                "permguard-language-cedar",
                "permguard-language-dogwood",
                "cedar-policy",
                "dogwood-language",
            ][..],
        ),
        (
            "dogwood",
            &["permguard-language-dogwood", "dogwood-language"][..],
            &[
                "permguard-language-cedar",
                "permguard-language-rego",
                "regorus",
                "jsonschema",
            ][..],
        ),
    ] {
        let linked = carried_with("permguard-data-plane", features);
        for name in carried {
            if !linked.contains(*name) {
                problems.push(format!("built with `{features}`, it does not link {name}"));
            }
        }
        for name in absent.iter().chain(NEVER) {
            if linked.contains(*name) {
                problems.push(format!("built with `{features}`, it links {name}"));
            }
        }
    }
    assert!(
        problems.is_empty(),
        "an embedded Data Plane links what its features select:\n  {}",
        problems.join("\n  ")
    );
}

/// The client library carries the transports its consumer selects and no other (RD-10): built for
/// REST alone it links no tonic and no generated contract, whatever surfaces it serves; built for
/// gRPC it links them, and the stubs of a server in neither case.
#[test]
fn a_client_links_only_the_transports_it_selects() {
    const SURFACES: &str = "catalog,notp,decisions,events,pdp,temporal,host,authority,documents";
    let rest = carried_with("permguard-client", &format!("http,{SURFACES}"));
    let grpc = carried_with("permguard-client", &format!("grpc,{SURFACES}"));
    let mut problems = Vec::new();
    // Axum is tonic's own, for the router its default features carry: a gRPC client links it
    // through tonic, and a REST client not at all.
    for name in ["tonic", "prost", "permguard-contracts", "axum", "hyper"] {
        if rest.contains(name) {
            problems.push(format!("built for REST alone, it links {name}"));
        }
        if !grpc.contains(name) {
            problems.push(format!("built for gRPC, it does not link {name}"));
        }
    }
    for linked in [&rest, &grpc] {
        for name in [
            "permguard-server",
            "permguard-transport",
            "permguard-languages",
            "cedar-policy",
            "regorus",
        ] {
            if linked.contains(name) {
                problems.push(format!("a client links {name}"));
            }
        }
    }
    assert!(
        problems.is_empty(),
        "a client links the transports it selects:\n  {}",
        problems.join("\n  ")
    );
}
