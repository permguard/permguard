// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! One stream engine (WP-5.1): the Host owns it, and no Plane keeps a journal, a STATE or a reserve
//! of its own beyond the legacy engines `permguard_stream::engine::LEGACY_ENGINES` names, which
//! WP-6.1 and WP-6.2 adopt. A seeded engine is found wherever it is put.

#![allow(clippy::expect_used)]

use std::path::{Path, PathBuf};

use permguard_stream::engine::LEGACY_ENGINES;

/// The crates whose code is a Plane's, or a Plane's record library.
const PLANE_CRATES: [&str; 5] = [
    "crates/permguard-data-plane/src",
    "crates/permguard-control-plane/src",
    "crates/permguard-decisions/src",
    "crates/permguard-events/src",
    "crates/permguard-languages/src",
];

/// What marks a durable stream engine: a journal, the storage library's or a legacy one, a file
/// opened or flushed by hand, or the files a journal of its own keeps beside its segments.
const MARKERS: [&str; 8] = [
    "storage::journal",
    "journal::Journal",
    "Journal::open",
    "OpenOptions",
    "sync_data(",
    "\"RESERVE\"",
    "\"STATE\"",
    "\"seg-",
];

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// The Rust sources below `dir`, as paths relative to `root`.
fn sources(root: &Path, dir: &str) -> Vec<String> {
    let mut found = Vec::new();
    let mut pending = vec![root.join(dir)];
    while let Some(path) = pending.pop() {
        if path.is_dir() {
            for entry in std::fs::read_dir(&path).expect("a directory") {
                pending.push(entry.expect("an entry").path());
            }
        } else if path.extension().is_some_and(|ext| ext == "rs")
            && !path.components().any(|part| part.as_os_str() == "tests")
            && path.file_name().is_none_or(|name| name != "tests.rs")
        {
            found.push(
                path.strip_prefix(root)
                    .expect("below the root")
                    .to_string_lossy()
                    .replace('\\', "/"),
            );
        }
    }
    found.sort();
    found
}

/// The sources among `files`, with their text, that carry a marker and are no legacy engine.
fn offenders<'a>(files: impl IntoIterator<Item = (&'a str, &'a str)>) -> Vec<String> {
    files
        .into_iter()
        .filter(|(path, _)| !LEGACY_ENGINES.contains(path))
        .filter_map(|(path, text)| {
            MARKERS
                .iter()
                .find(|marker| text.contains(*marker))
                .map(|marker| format!("{path}: {marker}"))
        })
        .collect()
}

#[test]
fn no_plane_owns_a_stream_engine_beyond_the_named_legacy() {
    let root = root();
    let files: Vec<(String, String)> = PLANE_CRATES
        .iter()
        .flat_map(|dir| sources(&root, dir))
        .map(|path| {
            let text = std::fs::read_to_string(root.join(&path)).expect("the source reads");
            (path, text)
        })
        .collect();
    assert!(files.len() > 20, "the Plane sources were found");
    let offenders = offenders(
        files
            .iter()
            .map(|(path, text)| (path.as_str(), text.as_str())),
    );
    assert!(
        offenders.is_empty(),
        "a Plane keeps a stream engine of its own; register a descriptor with the Host's engine \
         (`permguard_stream::engine`) instead:\n{}",
        offenders.join("\n")
    );
    // Every legacy engine still exists: one that moved, or was adopted, leaves the list.
    for legacy in LEGACY_ENGINES {
        assert!(
            root.join(legacy).is_file(),
            "`{legacy}` is listed as a legacy engine and is gone: take it off the list"
        );
    }
}

#[test]
fn a_seeded_stream_engine_is_found_wherever_it_is_put() {
    for marker in MARKERS {
        let text = format!("const FILE: &str = {marker};");
        let seeded = offenders([(
            "crates/permguard-data-plane/src/new_spool.rs",
            text.as_str(),
        )]);
        assert_eq!(seeded.len(), 1, "{marker}");
    }
    assert!(
        offenders([(LEGACY_ENGINES[0], "const STATE: &str = \"STATE\";")]).is_empty(),
        "a legacy engine is allowed"
    );
}
