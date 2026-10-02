// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The boundary registry equals the code: every untrusted decoder the scanned crates export is
//! registered with a bound and a fuzz target that calls it, and nothing registered is dangling.

#![allow(clippy::expect_used)]

use std::path::Path;

use permguard_conformance::boundaries::{self, Registry};

#[test]
fn test_the_boundary_registry_matches_the_exported_decoders_and_the_fuzz_targets() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let registry: Registry = serde_json::from_str(
        &std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("boundaries.json"))
            .expect("boundaries.json is readable"),
    )
    .expect("boundaries.json is a registry");
    let inventory = boundaries::inventory(&root);
    let manifest =
        std::fs::read_to_string(root.join("fuzz/Cargo.toml")).expect("fuzz/Cargo.toml is readable");

    let problems = boundaries::check(&registry, &inventory, &manifest, |path| {
        std::fs::read_to_string(root.join(path)).ok()
    });

    assert!(
        problems.is_empty(),
        "the boundary registry and the code disagree; update crates/permguard-conformance/boundaries.json \
         and the fuzz target in the same change:\n  {}",
        problems.join("\n  ")
    );
    assert!(
        inventory.len() >= 30,
        "the scan found the decoders ({})",
        inventory.len()
    );
}
