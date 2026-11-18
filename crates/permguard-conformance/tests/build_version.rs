// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The version a binary reports and stamps is `permguard_core::build::VERSION`: the release tag
//! when a release stamped it, the workspace version otherwise. The workspace version alone,
//! `CARGO_PKG_VERSION`, stays `0.1.0` across releases on purpose (`scripts/prepare-release.sh`), so
//! a record or a header that read it would say `0.1.0` on every released binary (BUG-0220: the
//! command line's offline audit records said `0.1.0` while `--version` said the tag).

#![allow(clippy::expect_used)]

use std::path::{Path, PathBuf};

/// The files that may read the workspace version, and why.
const ALLOWED: &[(&str, &str)] = &[
    (
        "permguard-core/src/build.rs",
        "defines `build::VERSION`, falling back to the workspace version for an unstamped build",
    ),
    (
        "permguard-languages/src/registry.rs",
        "`ENGINE_VERSION`, the engine identity the manifest load gate compares, not a release",
    ),
];

fn sources(directory: &Path, found: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(directory).expect("a source directory reads") {
        let path = entry.expect("an entry").path();
        if path.is_dir() {
            sources(&path, found);
        } else if path.extension().is_some_and(|extension| extension == "rs") {
            found.push(path);
        }
    }
}

#[test]
fn test_no_shipped_source_reports_the_workspace_version_for_the_build() {
    let crates = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
    let mut problems = Vec::new();
    let mut read = 0;
    let mut allowed_seen = 0;
    for package in std::fs::read_dir(&crates).expect("the crates read") {
        let package = package.expect("a crate").path();
        let source = package.join("src");
        if !source.is_dir() {
            continue;
        }
        let mut files = Vec::new();
        sources(&source, &mut files);
        for file in files {
            read += 1;
            let text = std::fs::read_to_string(&file).expect("a source reads");
            if !text.contains("CARGO_PKG_VERSION") {
                continue;
            }
            let named = file
                .strip_prefix(&crates)
                .expect("under the crates")
                .to_string_lossy()
                .replace('\\', "/");
            if ALLOWED.iter().any(|(allowed, _)| *allowed == named) {
                allowed_seen += 1;
            } else {
                problems.push(named);
            }
        }
    }
    assert!(read > 100, "the sources are read: {read}");
    assert_eq!(
        allowed_seen,
        ALLOWED.len(),
        "every allowed file still reads it"
    );
    assert!(
        problems.is_empty(),
        "read the version through `permguard_core::build::VERSION`, which a release stamps:\n  {}",
        problems.join("\n  ")
    );
}
