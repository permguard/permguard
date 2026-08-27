// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! Finding the authored manifest in a working tree: `manifest.yml` **or** `manifest.yaml` at the
//! workspace root — both accepted, both present is ambiguity and rejects.
//!
//! What the YAML *means* is not decided here. That conversion needs the languages (a partition
//! that spells out no media types gets them from its runtime's), so it lives beside them, in
//! [`permguard_languages::manifest_file`], and everything that reads an authored manifest reads it
//! through the same function. This module is the half that needs a working tree.

use permguard_objects::manifest::Manifest;

use permguard_control_client::Store;

pub use permguard_languages::manifest_file::{
    InputSection, ManifestFile, MetadataSection, PartitionSection, ProfileSection,
    RequirementSection, RuntimeSection, to_yaml,
};

pub const MANIFEST_YML: &str = "manifest.yml";
pub const MANIFEST_YAML: &str = "manifest.yaml";

/// Finds the manifest file: `.yml`, `.yaml`, both → error, none → `None`.
pub fn find(store: &dyn Store) -> Result<Option<&'static str>, String> {
    match (store.exists(MANIFEST_YML), store.exists(MANIFEST_YAML)) {
        (true, true) => Err(
            "both manifest.yml and manifest.yaml exist: two manifests is ambiguity — delete one"
                .to_owned(),
        ),
        (true, false) => Ok(Some(MANIFEST_YML)),
        (false, true) => Ok(Some(MANIFEST_YAML)),
        (false, false) => Ok(None),
    }
}

/// Loads and converts the authored manifest into the canonical model.
pub fn load(store: &dyn Store) -> Result<Manifest, String> {
    let Some(path) = find(store)? else {
        return Err(
            "no manifest: expected manifest.yml (or manifest.yaml) at the workspace root"
                .to_owned(),
        );
    };
    let bytes = store.read(path)?.unwrap_or_default();

    permguard_languages::manifest_file::from_yaml(&bytes).map_err(|error| format!("{path} {error}"))
}
