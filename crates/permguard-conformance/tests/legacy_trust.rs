// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! WP-7.7: the configured URL and TLS trust, the first-contact ring and the per-plane key endpoints
//! as authority are gone from every Plane. A Data Plane mirrors over `policy.mirror` task sessions
//! only, its statements verified under a pinned `control.attest` set — a membership's, or the
//! Host's own for its local task — so no Plane source reaches a Control Plane over a URL client,
//! and the configuration no longer has a server list to carry. A path brought back fails here.

#![allow(clippy::expect_used)]

use std::path::{Path, PathBuf};

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// The Rust sources below `dir`, as paths relative to the repository.
fn sources(dir: &str) -> Vec<PathBuf> {
    fn walk(path: &Path, found: &mut Vec<PathBuf>) {
        for entry in std::fs::read_dir(path)
            .expect("the directory lists")
            .flatten()
        {
            let path = entry.path();
            if path.is_dir() {
                walk(&path, found);
            } else if path.extension().is_some_and(|extension| extension == "rs") {
                found.push(path);
            }
        }
    }
    let mut found = Vec::new();
    walk(&root().join(dir), &mut found);
    found
}

/// What only a client that reaches a Control Plane over a URL uses: the URL remote, its HTTP
/// half, and the catalog client that lists what a server holds.
const URL_CLIENT: [&str; 3] = ["AnyRemote", "RemoteHttp", "catalog::client("];

/// What carried a mirror source: the configured server list.
const SERVER_LIST: [&str; 3] = ["MirrorSource", "mirror_sources", "MirrorServerSection"];

#[test]
fn no_plane_reaches_a_control_plane_over_a_url_to_mirror_it() {
    let mut found = Vec::new();
    for dir in [
        "crates/permguard-data-plane/src",
        "crates/permguard-control-plane/src",
        "crates/permguard-server/src",
    ] {
        for path in sources(dir) {
            let text = std::fs::read_to_string(&path).expect("the source reads");
            for marker in URL_CLIENT {
                if text.contains(marker) {
                    found.push(format!("{}: {marker}", path.display()));
                }
            }
        }
    }
    assert!(
        found.is_empty(),
        "a Plane mirrors over a URL again, the trust WP-7.7 removed:\n{}",
        found.join("\n")
    );
}

#[test]
fn the_configuration_carries_no_server_list() {
    let mut found = Vec::new();
    for dir in [
        "crates/permguard-core/src",
        "crates/permguard-server/src",
        "crates/permguard-data-plane/src",
    ] {
        for path in sources(dir) {
            let text = std::fs::read_to_string(&path).expect("the source reads");
            for marker in SERVER_LIST {
                if text.contains(marker) {
                    found.push(format!("{}: {marker}", path.display()));
                }
            }
        }
    }
    assert!(
        found.is_empty(),
        "a mirror source is configured again:\n{}",
        found.join("\n")
    );
}

/// Every shipped configuration, the chart's values and the lab's included, names no server list:
/// the file a deployment would start from would stop it.
#[test]
fn no_shipped_file_names_the_retired_server_list() {
    let mut files: Vec<PathBuf> = Vec::new();
    for dir in ["crates/permguard-all-in-one", "crates/permguard-data-plane"] {
        for entry in std::fs::read_dir(root().join(dir))
            .expect("lists")
            .flatten()
        {
            let name = entry.file_name().to_string_lossy().into_owned();
            if name.starts_with("config") && name.ends_with(".yml") {
                files.push(entry.path());
            }
        }
    }
    for file in [
        "charts/permguard/values.yaml",
        "charts/permguard/values-production.yaml",
        "lab/compose/all-in-one.yml",
        "lab/compose/control-plane.yml",
        "lab/compose/data-plane.yml",
        "lab/compose/data-plane-temporal.yml",
    ] {
        files.push(root().join(file));
    }
    let named: Vec<String> = files
        .iter()
        .filter(|path| {
            std::fs::read_to_string(path)
                .expect("the file reads")
                .lines()
                .any(|line| line.trim_start().trim_start_matches('#').trim() == "servers:")
        })
        .map(|path| path.display().to_string())
        .collect();
    assert!(named.is_empty(), "the retired `servers:` list: {named:?}");
}
