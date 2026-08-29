// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The authored manifest: the YAML an author writes, and the canonical model it means.
//!
//! # Why it lives beside the languages
//!
//! Converting the YAML into the model is not transcription. A partition that spells out no media
//! types gets them from its runtime's language — the policy type, plus the schema type when it
//! declares a schema — and only whoever holds the languages can answer that. So the conversion
//! lives here, once, and everything that reads an authored manifest reads it through this: the CLI
//! that builds a workspace, and the tests that drive an example through a real plane. A second
//! reader is a second opinion about what `manifest.yml` means, and the first field it forgets is
//! the one nobody notices until a request is refused for a reason nobody can see.
//!
//! The store-aware half — which of `manifest.yml` and `manifest.yaml` is present, and reading it —
//! stays with whoever has a working tree. This half is bytes in, model out.
//!
//! # Every section refuses a field it does not know
//!
//! `deny_unknown_fields`, on all of them, and it is not tidiness. Serde's default is to ignore
//! what it cannot place, so `requred: true` was accepted and `required` stayed `false` — a typo
//! turning a partition whose data is mandatory into one where it is optional, silently, in a file
//! whose whole job is to say what is mandatory. A manifest is configuration for an authorization
//! system: the failure mode of ignoring a key is a control that quietly is not there.
//!
//! This is the opposite of the rule the *request* contract follows, where an unknown field is
//! ignored because forward compatibility is the reader's duty. A request comes from a caller who
//! may be newer than this build; a manifest comes from the repository this build is serving, and
//! the version skew there is answered by the runtime constraints instead.

use std::collections::BTreeMap;

use permguard_objects::manifest::{
    ArtifactContract, HistoryScope, InputContract, Manifest, Partition, Profile, Requirement,
    Runtime,
};
use permguard_objects::semver::Constraint;
use serde::{Deserialize, Serialize};

/// The YAML shape, exactly as the documentation shows it.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ManifestFile {
    pub metadata: MetadataSection,
    pub runtimes: BTreeMap<String, RuntimeSection>,
    pub partitions: BTreeMap<String, PartitionSection>,
    pub profiles: BTreeMap<String, ProfileSection>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
pub struct RuntimeSection {
    pub language: RequirementSection,
    pub engine: RequirementSection,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RequirementSection {
    pub name: String,
    pub constraint: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PartitionSection {
    pub runtime: String,
    #[serde(default)]
    pub media_types: Vec<String>,
    /// The legacy one-schema flag, still how Cedar and Rego partitions declare theirs.
    #[serde(default)]
    pub schema: bool,
    /// The typed artifact contracts this partition declares, for a runtime that has several.
    ///
    /// An alternative to `schema`, not an addition: a partition states its contents one way or
    /// the other, and declaring both is refused.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub artifacts: Vec<ArtifactSection>,
    /// How this partition's temporal history is scoped, when it has to say.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub history: Option<HistorySection>,
    /// What a request may hand this partition, when it may hand it anything.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub input: Option<InputSection>,
}

/// One artifact contract, by registered type.
///
/// The author names a type; the registry answers what part it plays, how many are allowed and how
/// one is validated. `required` may tighten an optional artifact; it cannot excuse a required one.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ArtifactSection {
    pub r#type: String,
    #[serde(default)]
    pub required: bool,
}

/// How a temporal partition's history is scoped.
///
/// Only ever written to acknowledge a schema with no universal pin, whose every evaluation ranges
/// over the whole retained history. An operator states that out loud or the partition is refused.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct HistorySection {
    pub scope: HistoryScopeSection,
}

/// The scope as YAML spells it.
///
/// A presentation of [`HistoryScope`], not that type with serde bolted on: the canonical model
/// carries no serialization framework, because what a manifest *is* on the wire is its CBOR
/// encoding and nothing else. This is the same separation `InputSection` keeps.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum HistoryScopeSection {
    Global,
}

impl From<HistoryScopeSection> for HistoryScope {
    fn from(scope: HistoryScopeSection) -> Self {
        match scope {
            HistoryScopeSection::Global => Self::Global,
        }
    }
}

impl From<HistoryScope> for HistoryScopeSection {
    fn from(scope: HistoryScope) -> Self {
        match scope {
            HistoryScope::Global => Self::Global,
        }
    }
}

/// The one kind of request-supplied input a partition accepts.
///
/// Declared by the ledger and not chosen by the caller: what data *is* decides which parser reads
/// it, and a caller picking that would be picking the parser for bytes it also supplies.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct InputSection {
    pub r#type: String,
    /// Whether a request must address this partition. Default `false`.
    #[serde(default)]
    pub required: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProfileSection {
    pub r#type: String,
    pub partitions: Vec<String>,
}

/// The model an authored manifest means, with every rule of the model enforced.
///
/// Round-trips through the model's own encoder and decoder, so an author is refused exactly what a
/// server would refuse — then asks this build whether it could serve the result at all, which is
/// the question the plane asks at load and the control plane asks at ingest.
pub fn from_yaml(bytes: &[u8]) -> Result<Manifest, String> {
    let file: ManifestFile =
        serde_norway::from_slice(bytes).map_err(|error| format!("does not parse: {error}"))?;
    let manifest = to_model(&file)?;
    let decoded = Manifest::decode(&manifest.encode()).map_err(|error| error.to_string())?;
    crate::registry::check_manifest(&decoded).map_err(|error| error.to_string())?;

    Ok(decoded)
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
            let plugin = crate::language(&runtime.language.name)
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
                artifacts: partition
                    .artifacts
                    .iter()
                    .map(|artifact| ArtifactContract {
                        r#type: artifact.r#type.clone(),
                        required: artifact.required,
                    })
                    .collect(),
                history: partition
                    .history
                    .as_ref()
                    .map(|history| history.scope.into()),
                input: partition.input.as_ref().map(|input| InputContract {
                    r#type: input.r#type.clone(),
                    required: input.required,
                }),
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
                        artifacts: partition
                            .artifacts
                            .iter()
                            .map(|artifact| ArtifactSection {
                                r#type: artifact.r#type.clone(),
                                required: artifact.required,
                            })
                            .collect(),
                        history: partition.history.map(|scope| HistorySection {
                            scope: scope.into(),
                        }),
                        input: partition.input.as_ref().map(|input| InputSection {
                            r#type: input.r#type.clone(),
                            required: input.required,
                        }),
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

#[cfg(test)]
mod tests {
    use super::*;

    const WELL_FORMED: &str = r#"
metadata: { kind: policy, name: l }
runtimes:
  cedar:
    language: { name: cedar, constraint: ">=4.0.0" }
    engine:   { name: permguard, constraint: ">=0.1.0 <0.2.0" }
partitions:
  p:
    runtime: cedar
    schema: false
    input: { type: permguard.cedar.entities.v1, required: true }
profiles:
  default: { type: permguard.api.pdp.native.v1, partitions: [p] }
"#;

    #[test]
    fn a_well_formed_manifest_becomes_the_model() {
        let manifest = from_yaml(WELL_FORMED.as_bytes()).expect("it is well formed");
        let input = manifest.partitions["p"]
            .input
            .as_ref()
            .expect("the partition accepts an input");

        assert_eq!(input.r#type, "permguard.cedar.entities.v1");
        assert!(input.required);
    }

    /// A key nobody knows is a refusal, not a shrug.
    ///
    /// `requred` was accepted and `required` stayed `false`: a partition whose data is mandatory
    /// became one where it is optional, from one transposed letter, in the file whose whole job is
    /// to say what is mandatory. Nothing in the run would ever have mentioned it.
    #[test]
    fn a_misspelt_key_is_refused_rather_than_ignored() {
        let typo = WELL_FORMED.replace("required: true", "requred: true");
        let refused = from_yaml(typo.as_bytes()).expect_err("`requred` is not a field");

        assert!(refused.contains("requred"), "{refused}");

        // And in every other section of the file, not only that one.
        for (what, from, to) in [
            ("a partition", "schema: false", "schemas: false"),
            (
                "a runtime",
                "language: { name: cedar",
                "languages: { name: cedar",
            ),
            ("the metadata", "kind: policy", "kinds: policy"),
            (
                "a profile",
                "type: permguard.api.pdp.native.v1",
                "types: permguard.api.pdp.native.v1",
            ),
            ("the file itself", "profiles:", "profile:"),
        ] {
            assert!(
                from_yaml(WELL_FORMED.replace(from, to).as_bytes()).is_err(),
                "{what}: an unknown key was ignored"
            );
        }
    }

    #[test]
    fn the_yaml_and_the_model_round_trip() {
        let manifest = from_yaml(WELL_FORMED.as_bytes()).expect("it is well formed");
        let rendered = to_yaml(&manifest).expect("it renders");

        assert_eq!(
            from_yaml(rendered.as_bytes()).expect("and reads back"),
            manifest,
            "what `pull` writes is what `apply` would read"
        );
    }
}
