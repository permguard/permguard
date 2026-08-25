// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The authored manifest: `manifest.yml` **or** `manifest.yaml` at the
//! workspace root — both accepted, both present is ambiguity and rejects.
//! The YAML is the author's presentation; the canonical CBOR blob is built
//! from it on push.

use std::collections::BTreeMap;

use permguard_objects::manifest::{Manifest, Partition, Profile, Requirement, Runtime};
use permguard_objects::semver::Constraint;
use serde::{Deserialize, Serialize};

use permguard_control_client::Store;

pub const MANIFEST_YML: &str = "manifest.yml";
pub const MANIFEST_YAML: &str = "manifest.yaml";

/// The YAML shape, exactly as the documentation shows it.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ManifestFile {
    pub metadata: MetadataSection,
    pub runtimes: BTreeMap<String, RuntimeSection>,
    pub partitions: BTreeMap<String, PartitionSection>,
    pub profiles: BTreeMap<String, ProfileSection>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MetadataSection {
    pub kind: String,
    pub name: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub author: String,
    #[serde(default)]
    pub license: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuntimeSection {
    pub language: RequirementSection,
    pub engine: RequirementSection,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RequirementSection {
    pub name: String,
    pub constraint: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PartitionSection {
    pub runtime: String,
    #[serde(default)]
    pub media_types: Vec<String>,
    #[serde(default)]
    pub schema: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProfileSection {
    pub r#type: String,
    pub partitions: Vec<String>,
}

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

/// Loads and converts the authored manifest into the canonical model —
/// every rule of the model enforced by round-tripping through its own
/// encoder and decoder, so the client refuses exactly what the server would.
pub fn load(store: &dyn Store) -> Result<Manifest, String> {
    let Some(path) = find(store)? else {
        return Err(
            "no manifest: expected manifest.yml (or manifest.yaml) at the workspace root"
                .to_owned(),
        );
    };
    let bytes = store.read(path)?.unwrap_or_default();
    let file: ManifestFile = serde_norway::from_slice(&bytes)
        .map_err(|error| format!("{path} does not parse: {error}"))?;
    let manifest = to_model(&file)?;
    // The same validation the server runs at ingest: fail fast, same words.
    Manifest::decode(&manifest.encode()).map_err(|error| error.to_string())
}

fn to_model(file: &ManifestFile) -> Result<Manifest, String> {
    let requirement = |section: &RequirementSection| -> Result<Requirement, String> {
        Ok(Requirement {
            name: section.name.clone(),
            constraint: Constraint::parse(&section.constraint)
                .map_err(|error| format!("constraint `{}`: {error}", section.constraint))?,
        })
    };
    let mut manifest = Manifest {
        kind: file.metadata.kind.clone(),
        name: file.metadata.name.clone(),
        description: file.metadata.description.clone(),
        author: file.metadata.author.clone(),
        license: file.metadata.license.clone(),
        ..Manifest::default()
    };
    for (key, runtime) in &file.runtimes {
        manifest.runtimes.insert(
            key.clone(),
            Runtime {
                language: requirement(&runtime.language)?,
                engine: requirement(&runtime.engine)?,
            },
        );
    }
    for (name, partition) in &file.partitions {
        // Media types may be spelled out or defaulted from the runtime's
        // language: the family's policy type, plus the schema type when
        // `schema: true`.
        let mut media_types = partition.media_types.clone();
        if media_types.is_empty() {
            let runtime = file
                .runtimes
                .get(&partition.runtime)
                .ok_or_else(|| format!("partition `{name}` names an undeclared runtime"))?;
            let plugin = permguard_languages::language(&runtime.language.name)
                .ok_or_else(|| format!("no built-in plugin for `{}`", runtime.language.name))?;
            media_types.push(plugin.policy_media_type().to_owned());
            if partition.schema {
                media_types.push(
                    plugin
                        .schema_media_type()
                        .ok_or_else(|| format!("`{}` has no schema media type", plugin.name()))?
                        .to_owned(),
                );
            }
        }
        manifest.partitions.insert(
            name.clone(),
            Partition {
                runtime: partition.runtime.clone(),
                media_types,
                schema: partition.schema,
            },
        );
    }
    for (name, profile) in &file.profiles {
        manifest.profiles.insert(
            name.clone(),
            Profile {
                r#type: profile.r#type.clone(),
                partitions: profile.partitions.clone(),
            },
        );
    }
    Ok(manifest)
}

/// Renders a model manifest back to YAML — what `pull` materializes when the
/// workspace has no manifest file yet.
pub fn to_yaml(manifest: &Manifest) -> Result<String, String> {
    let file = ManifestFile {
        metadata: MetadataSection {
            kind: manifest.kind.clone(),
            name: manifest.name.clone(),
            description: manifest.description.clone(),
            author: manifest.author.clone(),
            license: manifest.license.clone(),
        },
        runtimes: manifest
            .runtimes
            .iter()
            .map(|(key, runtime)| {
                (
                    key.clone(),
                    RuntimeSection {
                        language: RequirementSection {
                            name: runtime.language.name.clone(),
                            constraint: runtime.language.constraint.to_string(),
                        },
                        engine: RequirementSection {
                            name: runtime.engine.name.clone(),
                            constraint: runtime.engine.constraint.to_string(),
                        },
                    },
                )
            })
            .collect(),
        partitions: manifest
            .partitions
            .iter()
            .map(|(name, partition)| {
                (
                    name.clone(),
                    PartitionSection {
                        runtime: partition.runtime.clone(),
                        media_types: partition.media_types.clone(),
                        schema: partition.schema,
                    },
                )
            })
            .collect(),
        profiles: manifest
            .profiles
            .iter()
            .map(|(name, profile)| {
                (
                    name.clone(),
                    ProfileSection {
                        r#type: profile.r#type.clone(),
                        partitions: profile.partitions.clone(),
                    },
                )
            })
            .collect(),
    };
    serde_norway::to_string(&file).map_err(|error| format!("rendering the manifest: {error}"))
}
