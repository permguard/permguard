// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The Compose lab, read (TD-3): what `docker-compose.lab.yml` declares, checked without Docker.
//! What the profiles prove when they run is `scripts/compose-lab.sh`'s; this is what keeps them
//! portable and their bootstrap a lab's.
//!
//! | Area          | Proven here                                                                                 |
//! | ------------- | ------------------------------------------------------------------------------------------- |
//! | profiles      | the five profiles the blueprint names, each with its Hosts and the lab's authority          |
//! | portability   | no fixed host port, no loopback alias, no host network, no Linux-only interface setup       |
//! | reuse         | the Data Planes of a profile share one static file and each keeps its own volume            |
//! | identity      | each Host serves under its own service name, the name its certificate is issued to          |
//! | tokens        | no enrollment token in the examples, the chart or the lab's files                           |

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use serde_norway::Value;

const PROFILES: [&str; 5] = [
    "all-in-one",
    "split-plane",
    "multi-data-plane",
    "multi-group",
    "temporal-replicas",
];

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// The Compose file, its anchors and merge keys resolved as Compose resolves them.
fn compose() -> Value {
    let text = std::fs::read_to_string(root().join("docker-compose.lab.yml")).expect("the file");
    let mut value: Value = serde_norway::from_str(&text).expect("YAML");
    value.apply_merge().expect("merge keys");
    for (_, service) in services_of(&mut value) {
        service.apply_merge().expect("merge keys");
    }
    value
}

fn services_of(value: &mut Value) -> Vec<(String, &mut Value)> {
    value
        .get_mut("services")
        .and_then(Value::as_mapping_mut)
        .expect("services")
        .iter_mut()
        .map(|(name, service)| (name.as_str().expect("a name").to_owned(), service))
        .collect()
}

fn services(value: &Value) -> BTreeMap<String, Value> {
    value["services"]
        .as_mapping()
        .expect("services")
        .iter()
        .map(|(name, service)| (name.as_str().expect("a name").to_owned(), service.clone()))
        .collect()
}

fn strings(value: &Value) -> Vec<String> {
    value
        .as_sequence()
        .map(|items| {
            items
                .iter()
                .map(|item| item.as_str().expect("a string").to_owned())
                .collect()
        })
        .unwrap_or_default()
}

/// The services a profile starts.
fn in_profile(all: &BTreeMap<String, Value>, profile: &str) -> BTreeSet<String> {
    all.iter()
        .filter(|(_, service)| strings(&service["profiles"]).iter().any(|p| p == profile))
        .map(|(name, _)| name.clone())
        .collect()
}

/// The lab's Hosts: the services that run `permguard-lab serve`.
fn hosts(all: &BTreeMap<String, Value>) -> BTreeMap<String, Value> {
    all.iter()
        .filter(|(_, service)| {
            strings(&service["command"])
                .first()
                .is_some_and(|c| c == "serve")
        })
        .map(|(name, service)| (name.clone(), service.clone()))
        .collect()
}

#[test]
fn every_profile_the_blueprint_names_runs_its_hosts_and_the_lab_authority() {
    let all = services(&compose());
    let expected: [(&str, &[&str]); 5] = [
        ("all-in-one", &["all-in-one"]),
        ("split-plane", &["control-plane", "data-plane"]),
        (
            "multi-data-plane",
            &["control-plane", "data-plane-a", "data-plane-b"],
        ),
        (
            "multi-group",
            &["control-plane", "data-plane-acme", "data-plane-beta"],
        ),
        (
            "temporal-replicas",
            &["control-plane", "temporal-a", "temporal-b"],
        ),
    ];
    let hosts = hosts(&all);
    for (profile, members) in expected {
        let started = in_profile(&all, profile);
        let served: BTreeSet<String> = started
            .iter()
            .filter(|name| hosts.contains_key(*name))
            .cloned()
            .collect();
        let members: BTreeSet<String> = members.iter().map(|m| (*m).to_owned()).collect();
        assert_eq!(served, members, "{profile}: the Hosts it starts");
        for job in ["lab-pki", "lab-catalog"] {
            assert!(started.contains(job), "{profile}: {job}");
        }
        assert_eq!(
            started.contains("lab-enroll"),
            profile != "all-in-one",
            "{profile}: enrollment, which only a profile with a separate Data Plane has"
        );
    }
    // The assertions' container is never started by `up`.
    assert_eq!(strings(&all["lab"]["profiles"]), ["tools"]);
}

#[test]
fn no_profile_depends_on_a_fixed_host_port_a_loopback_alias_or_the_host_network() {
    let all = services(&compose());
    for profile in PROFILES {
        for name in in_profile(&all, profile) {
            let service = &all[&name];
            for port in strings(&service["ports"]) {
                // `127.0.0.1::<port>`: the host's loopback, a port the engine picks.
                let mut parts = port.splitn(3, ':');
                let (address, host_port, container) = (parts.next(), parts.next(), parts.next());
                assert_eq!(address, Some("127.0.0.1"), "{name}: {port}");
                assert_eq!(host_port, Some(""), "{name}: {port} fixes a host port");
                assert!(
                    container.is_some_and(|c| c.parse::<u16>().is_ok()),
                    "{name}: {port}"
                );
            }
            for key in [
                "network_mode",
                "extra_hosts",
                "cap_add",
                "sysctls",
                "networks",
            ] {
                assert!(
                    service.get(key).is_none(),
                    "{name}: `{key}` in a lab profile"
                );
            }
        }
    }
    for file in lab_files() {
        let text = std::fs::read_to_string(&file).expect("a lab file");
        for forbidden in [
            "127.0.0.2",
            "network_mode",
            "host.docker.internal",
            "ifconfig",
            "ip addr",
        ] {
            assert!(
                !text.contains(forbidden),
                "{}: `{forbidden}`",
                file.display()
            );
        }
    }
}

/// The lab's own files: the Compose file's lab half is checked above; these are what it mounts.
fn lab_files() -> Vec<PathBuf> {
    let directory = root().join("lab/compose");
    let mut files: Vec<PathBuf> = std::fs::read_dir(&directory)
        .expect("lab/compose")
        .map(|entry| entry.expect("an entry").path())
        .filter(|path| path.is_file())
        .collect();
    files.sort();
    assert!(files.len() >= 6, "{files:?}");
    files
}

#[test]
fn the_data_planes_of_a_profile_share_one_static_file_and_keep_their_own_volumes() {
    let all = services(&compose());
    let hosts = hosts(&all);
    for profile in PROFILES {
        let planes: Vec<(&String, &Value)> = hosts
            .iter()
            .filter(|(name, _)| in_profile(&all, profile).contains(*name))
            .filter(|(_, service)| strings(&service["command"])[1] == "permguard-data-plane")
            .collect();
        let configs: BTreeSet<String> = planes
            .iter()
            .map(|(_, service)| strings(&service["command"])[2].clone())
            .collect();
        assert!(configs.len() <= 1, "{profile}: one file, not {configs:?}");
        let volumes: BTreeSet<String> = planes
            .iter()
            .map(|(name, service)| {
                strings(&service["volumes"])
                    .into_iter()
                    .find(|mount| mount.ends_with(":/var/lib/permguard"))
                    .unwrap_or_else(|| panic!("{name}: no state volume"))
            })
            .collect();
        assert_eq!(volumes.len(), planes.len(), "{profile}: a volume per Host");
    }
    // Every static file a Host is started on exists, but the one the catalog renders.
    for (name, service) in &hosts {
        let config = strings(&service["command"])[2].clone();
        if let Some(file) = config.strip_prefix("/opt/permguard/lab/") {
            assert!(
                root().join("lab/compose").join(file).is_file(),
                "{name}: {config}"
            );
        } else {
            assert_eq!(config, "/lab/state/data-plane-temporal.yml", "{name}");
            assert!(root().join("lab/compose/data-plane-temporal.yml").is_file());
        }
    }
}

#[test]
fn a_host_only_reads_the_lab_authority_and_the_coordinator_keeps_no_producer_key() {
    let all = services(&compose());
    for (name, service) in hosts(&all) {
        let mounts = strings(&service["volumes"]);
        assert!(
            mounts.contains(&"lab:/lab:ro".to_owned()),
            "{name}: {mounts:?}"
        );
        assert!(
            !mounts.contains(&"lab:/lab".to_owned()),
            "{name} may write the authority"
        );
    }
    // The coordinator verifies what members ship under the rings their memberships pinned: no
    // store that would need a producer key file, and no key file named.
    let config: serde_norway::Value = serde_norway::from_str(
        &std::fs::read_to_string(root().join("lab/compose/control-plane.yml")).expect("the file"),
    )
    .expect("YAML");
    let plane = &config["controlPlane"];
    for key in ["decisions", "events"] {
        assert!(plane.get(key).is_none(), "controlPlane.{key}");
    }
    for file in lab_files() {
        let text = std::fs::read_to_string(&file).expect("a lab file");
        assert!(!text.contains("producer_keys"), "{}", file.display());
        assert!(!text.contains(".jwks"), "{}", file.display());
    }
}

#[test]
fn each_host_serves_under_its_own_service_name() {
    let all = services(&compose());
    let script =
        std::fs::read_to_string(root().join("lab/compose/permguard-lab.sh")).expect("the script");
    // The script's `hosts=(…)`: every name its authority issues a certificate to.
    let start = script.find("\nhosts=(").expect("the script's hosts") + "\nhosts=(".len();
    let end = start + script[start..].find(')').expect("the list's end");
    let issued: BTreeSet<&str> = script[start..end].split_whitespace().collect();
    for (name, service) in hosts(&all) {
        assert_eq!(
            service["environment"]["LAB_HOST"].as_str(),
            Some(name.as_str()),
            "{name}: the name its certificate is issued to"
        );
        // The lab's authority issues it a certificate.
        assert!(
            issued.contains(name.as_str()),
            "{name}: the lab's authority issues it no certificate"
        );
        assert!(
            service["healthcheck"]["test"].as_sequence().is_some(),
            "{name}: no health check for its dependents to wait on"
        );
    }
}

#[test]
fn no_enrollment_token_is_embedded_in_the_examples_the_chart_or_the_lab() {
    let mut found = Vec::new();
    for directory in ["examples", "charts", "lab"] {
        walk(&root().join(directory), &mut |path| {
            let Ok(text) = std::fs::read_to_string(path) else {
                return;
            };
            // An invitation's handoff — its id and its secret together — as JSON, YAML or an
            // environment variable.
            let invitation = text.contains("invite_id");
            let secret = text.contains("\"token\"")
                || text
                    .lines()
                    .any(|line| line.trim_start().starts_with("token:"))
                || text.contains("_TOKEN=");
            if invitation && secret {
                found.push(path.to_path_buf());
            }
        });
    }
    let compose = std::fs::read_to_string(root().join("docker-compose.lab.yml")).expect("file");
    assert!(!compose.contains("invite_id"), "the Compose file");
    assert!(found.is_empty(), "enrollment tokens: {found:?}");
}

fn walk(directory: &Path, visit: &mut dyn FnMut(&Path)) {
    for entry in std::fs::read_dir(directory).expect("a directory") {
        let path = entry.expect("an entry").path();
        if path.is_dir() {
            walk(&path, visit);
        } else {
            visit(&path);
        }
    }
}
