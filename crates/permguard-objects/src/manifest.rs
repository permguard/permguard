// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The ledger manifest — what a ledger is, what it holds, and the contracts
//! it can be consumed through. A blob (`application/vnd.permguard.manifest.v1+cbor`),
//! exactly one per commit, pointed at by the commit and present as the root
//! entry `manifest`.
//!
//! The wire form is the canonical CBOR profile with integer keys; the YAML
//! the author writes is a presentation the workspace maps onto this.

use std::collections::BTreeMap;
use std::fmt;

use crate::cbor::{self, Value};
use crate::grammar;
use crate::semver::{Constraint, SemverError, Version};

/// The registered media type of the manifest blob.
pub const MEDIA_TYPE: &str = "application/vnd.permguard.manifest.v1+cbor";

/// The ledger kinds this build understands. One kind per ledger, never mixed.
pub const KIND_POLICY: &str = "policy";

/// The evaluation-contract types this build understands.
pub const PROFILE_PDP_V1: &str = "permguard.pdp.v1";

/// One runtime requirement: a name and the semver range that satisfies it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Requirement {
    pub name: String,
    pub constraint: Constraint,
}

/// One runtime: the language the sources speak and the engine allowed to
/// run them — two independent constraints, on purpose.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Runtime {
    pub language: Requirement,
    pub engine: Requirement,
}

/// One partition's rules.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Partition {
    /// Which runtime this partition's content speaks.
    pub runtime: String,
    /// The registered media types allowed inside.
    pub media_types: Vec<String>,
    /// Whether the partition carries a language schema.
    pub schema: bool,
}

/// One profile: the evaluation contract offered on top of some partitions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Profile {
    /// The contract type — language-agnostic, e.g. `permguard.pdp.v1`.
    pub r#type: String,
    /// The partitions the profile is built from.
    pub partitions: Vec<String>,
}

/// The manifest.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Manifest {
    /// The ledger's kind — `policy` today. Never mixed.
    pub kind: String,
    pub name: String,
    pub description: String,
    pub author: String,
    pub license: String,
    pub runtimes: BTreeMap<String, Runtime>,
    pub partitions: BTreeMap<String, Partition>,
    pub profiles: BTreeMap<String, Profile>,
}

// CBOR integer keys, normative.
const KEY_METADATA: i64 = 1;
const KEY_RUNTIMES: i64 = 2;
const KEY_PARTITIONS: i64 = 3;
const KEY_PROFILES: i64 = 4;
const META_KIND: i64 = 1;
const META_NAME: i64 = 2;
const META_DESCRIPTION: i64 = 3;
const META_AUTHOR: i64 = 4;
const META_LICENSE: i64 = 5;
const REQ_NAME: i64 = 1;
const REQ_CONSTRAINT: i64 = 2;
const RUNTIME_LANGUAGE: i64 = 1;
const RUNTIME_ENGINE: i64 = 2;
const PARTITION_RUNTIME: i64 = 1;
const PARTITION_MEDIA_TYPES: i64 = 2;
const PARTITION_SCHEMA: i64 = 3;
const PROFILE_TYPE: i64 = 1;
const PROFILE_PARTITIONS: i64 = 2;

impl Manifest {
    /// Encode as the canonical inner CBOR payload of the manifest blob.
    pub fn encode(&self) -> Vec<u8> {
        let text = |s: &str| Value::Text(s.to_owned());
        let requirement = |r: &Requirement| {
            Value::Map(vec![
                (Value::Int(REQ_NAME), text(&r.name)),
                (Value::Int(REQ_CONSTRAINT), text(&r.constraint.to_string())),
            ])
        };
        let metadata = Value::Map(vec![
            (Value::Int(META_KIND), text(&self.kind)),
            (Value::Int(META_NAME), text(&self.name)),
            (Value::Int(META_DESCRIPTION), text(&self.description)),
            (Value::Int(META_AUTHOR), text(&self.author)),
            (Value::Int(META_LICENSE), text(&self.license)),
        ]);
        let runtimes = Value::Map(
            self.runtimes
                .iter()
                .map(|(key, runtime)| {
                    (
                        text(key),
                        Value::Map(vec![
                            (Value::Int(RUNTIME_LANGUAGE), requirement(&runtime.language)),
                            (Value::Int(RUNTIME_ENGINE), requirement(&runtime.engine)),
                        ]),
                    )
                })
                .collect(),
        );
        let partitions = Value::Map(
            self.partitions
                .iter()
                .map(|(name, partition)| {
                    (
                        text(name),
                        Value::Map(vec![
                            (Value::Int(PARTITION_RUNTIME), text(&partition.runtime)),
                            (
                                Value::Int(PARTITION_MEDIA_TYPES),
                                Value::Array(
                                    partition.media_types.iter().map(|m| text(m)).collect(),
                                ),
                            ),
                            (Value::Int(PARTITION_SCHEMA), Value::Bool(partition.schema)),
                        ]),
                    )
                })
                .collect(),
        );
        let profiles = Value::Map(
            self.profiles
                .iter()
                .map(|(name, profile)| {
                    (
                        text(name),
                        Value::Map(vec![
                            (Value::Int(PROFILE_TYPE), text(&profile.r#type)),
                            (
                                Value::Int(PROFILE_PARTITIONS),
                                Value::Array(profile.partitions.iter().map(|p| text(p)).collect()),
                            ),
                        ]),
                    )
                })
                .collect(),
        );
        cbor::encode(&Value::Map(vec![
            (Value::Int(KEY_METADATA), metadata),
            (Value::Int(KEY_RUNTIMES), runtimes),
            (Value::Int(KEY_PARTITIONS), partitions),
            (Value::Int(KEY_PROFILES), profiles),
        ]))
    }

    /// Decode and structurally validate the canonical payload — the ingest
    /// rule of the manifest media type. Fail-closed on anything the schema
    /// does not list.
    pub fn decode(payload: &[u8]) -> Result<Self, ManifestError> {
        let value = cbor::decode_canonical(payload).map_err(|e| bad(format!("payload: {e}")))?;
        let pairs = as_map(&value, "manifest")?;

        let metadata = as_map(need(pairs, KEY_METADATA, "metadata")?, "metadata")?;
        let kind = get_text(metadata, META_KIND, "metadata.kind")?;
        if kind != KIND_POLICY {
            return Err(bad(format!("unknown ledger kind `{kind}`")));
        }

        let mut manifest = Manifest {
            kind,
            name: get_text(metadata, META_NAME, "metadata.name")?,
            description: get_text_or_default(metadata, META_DESCRIPTION)?,
            author: get_text_or_default(metadata, META_AUTHOR)?,
            license: get_text_or_default(metadata, META_LICENSE)?,
            ..Manifest::default()
        };

        for (key, value) in as_map(need(pairs, KEY_RUNTIMES, "runtimes")?, "runtimes")? {
            let Value::Text(key) = key else {
                return Err(bad("runtime keys must be strings"));
            };
            let runtime = as_map(value, "runtime")?;
            manifest.runtimes.insert(
                key.clone(),
                Runtime {
                    language: decode_requirement(need(runtime, RUNTIME_LANGUAGE, "language")?)?,
                    engine: decode_requirement(need(runtime, RUNTIME_ENGINE, "engine")?)?,
                },
            );
        }
        if manifest.runtimes.is_empty() {
            return Err(bad("a manifest declares at least one runtime"));
        }

        for (name, value) in as_map(need(pairs, KEY_PARTITIONS, "partitions")?, "partitions")? {
            let Value::Text(name) = name else {
                return Err(bad("partition names must be strings"));
            };
            grammar::validate_entry_name(name)
                .map_err(|e| bad(format!("partition `{name}`: {e}")))?;
            let partition = as_map(value, "partition")?;
            let media_types = match need(partition, PARTITION_MEDIA_TYPES, "media_types")? {
                Value::Array(items) => items
                    .iter()
                    .map(|v| match v {
                        Value::Text(t) => Ok(t.clone()),
                        _ => Err(bad("media_types must hold strings")),
                    })
                    .collect::<Result<Vec<_>, _>>()?,
                _ => return Err(bad("media_types must be an array")),
            };
            if media_types.is_empty() {
                return Err(bad(format!("partition `{name}` allows no media types")));
            }
            let schema = match need(partition, PARTITION_SCHEMA, "schema")? {
                Value::Bool(b) => *b,
                _ => return Err(bad("schema must be a boolean")),
            };
            let runtime = get_text(partition, PARTITION_RUNTIME, "partition.runtime")?;
            if !manifest.runtimes.contains_key(&runtime) {
                return Err(bad(format!(
                    "partition `{name}` names the runtime `{runtime}`, which is not declared"
                )));
            }
            manifest.partitions.insert(
                name.clone(),
                Partition {
                    runtime,
                    media_types,
                    schema,
                },
            );
        }
        if manifest.partitions.is_empty() {
            return Err(bad("a manifest declares at least one partition"));
        }

        for (name, value) in as_map(need(pairs, KEY_PROFILES, "profiles")?, "profiles")? {
            let Value::Text(name) = name else {
                return Err(bad("profile names must be strings"));
            };
            let profile = as_map(value, "profile")?;
            let r#type = get_text(profile, PROFILE_TYPE, "profile.type")?;
            if r#type != PROFILE_PDP_V1 {
                return Err(bad(format!("unknown profile type `{type}`", type = r#type)));
            }
            let partitions = match need(profile, PROFILE_PARTITIONS, "profile.partitions")? {
                Value::Array(items) => items
                    .iter()
                    .map(|v| match v {
                        Value::Text(t) => Ok(t.clone()),
                        _ => Err(bad("profile partitions must be strings")),
                    })
                    .collect::<Result<Vec<_>, _>>()?,
                _ => return Err(bad("profile partitions must be an array")),
            };
            for partition in &partitions {
                if !manifest.partitions.contains_key(partition) {
                    return Err(bad(format!(
                        "profile `{name}` names the partition `{partition}`, which is not declared"
                    )));
                }
            }
            manifest
                .profiles
                .insert(name.clone(), Profile { r#type, partitions });
        }

        Ok(manifest)
    }
}

/// What one consumer offers to the load gate: an engine name and version,
/// plus the language versions of its built-in plugins.
#[derive(Debug, Clone)]
pub struct ProvidedRuntime {
    pub language_name: String,
    pub language_version: Version,
    pub engine_name: String,
    pub engine_version: Version,
}

/// The fail-closed load gate of the specification: every runtime the
/// manifest declares must be satisfied by what this consumer provides —
/// language and engine, two independent checks — or the ledger is refused.
/// Never best-effort: an engine outside the declared range interpreting the
/// same policies differently is a silent authorization bypass.
pub fn check_load_gate(
    manifest: &Manifest,
    provided: &[ProvidedRuntime],
) -> Result<(), ManifestError> {
    for (key, runtime) in &manifest.runtimes {
        let offer = provided
            .iter()
            .find(|p| p.language_name == runtime.language.name)
            .ok_or_else(|| {
                bad(format!(
                    "runtime `{key}`: no built-in plugin for the language `{}`",
                    runtime.language.name
                ))
            })?;
        if !runtime.language.constraint.matches(offer.language_version) {
            return Err(bad(format!(
                "runtime `{key}`: language {} {} does not satisfy `{}`",
                runtime.language.name, offer.language_version, runtime.language.constraint
            )));
        }
        if offer.engine_name != runtime.engine.name
            || !runtime.engine.constraint.matches(offer.engine_version)
        {
            return Err(bad(format!(
                "runtime `{key}`: engine {} {} does not satisfy `{} {}`",
                offer.engine_name,
                offer.engine_version,
                runtime.engine.name,
                runtime.engine.constraint
            )));
        }
    }
    Ok(())
}

fn decode_requirement(value: &Value) -> Result<Requirement, ManifestError> {
    let pairs = as_map(value, "requirement")?;
    let constraint_text = get_text(pairs, REQ_CONSTRAINT, "constraint")?;
    Ok(Requirement {
        name: get_text(pairs, REQ_NAME, "name")?,
        constraint: Constraint::parse(&constraint_text)
            .map_err(|e: SemverError| bad(e.to_string()))?,
    })
}

fn as_map<'a>(value: &'a Value, what: &str) -> Result<&'a [(Value, Value)], ManifestError> {
    match value {
        Value::Map(pairs) => Ok(pairs),
        _ => Err(bad(format!("{what} must be a map"))),
    }
}

fn need<'a>(pairs: &'a [(Value, Value)], key: i64, what: &str) -> Result<&'a Value, ManifestError> {
    pairs
        .iter()
        .find(|(k, _)| *k == Value::Int(key))
        .map(|(_, v)| v)
        .ok_or_else(|| bad(format!("missing {what}")))
}

fn get_text(pairs: &[(Value, Value)], key: i64, what: &str) -> Result<String, ManifestError> {
    match need(pairs, key, what)? {
        Value::Text(t) if !t.is_empty() => Ok(t.clone()),
        Value::Text(_) => Err(bad(format!("{what} must not be empty"))),
        _ => Err(bad(format!("{what} must be text"))),
    }
}

fn get_text_or_default(pairs: &[(Value, Value)], key: i64) -> Result<String, ManifestError> {
    match pairs.iter().find(|(k, _)| *k == Value::Int(key)) {
        Some((_, Value::Text(t))) => Ok(t.clone()),
        Some(_) => Err(bad("metadata fields must be text")),
        None => Ok(String::new()),
    }
}

fn bad(detail: impl Into<String>) -> ManifestError {
    ManifestError {
        detail: detail.into(),
    }
}

/// Why a manifest was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManifestError {
    pub detail: String,
}

impl fmt::Display for ManifestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "manifest rejected: {}", self.detail)
    }
}

impl std::error::Error for ManifestError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Manifest {
        Manifest {
            kind: KIND_POLICY.into(),
            name: "acme-authz".into(),
            description: "example".into(),
            author: "Acme".into(),
            license: "Apache-2.0".into(),
            runtimes: BTreeMap::from([
                (
                    "cedar".to_string(),
                    Runtime {
                        language: Requirement {
                            name: "cedar".into(),
                            constraint: Constraint::parse(">=4.0.0").unwrap(),
                        },
                        engine: Requirement {
                            name: "permguard".into(),
                            constraint: Constraint::parse(">=0.1.0 <0.2.0").unwrap(),
                        },
                    },
                ),
                (
                    "rego".to_string(),
                    Runtime {
                        language: Requirement {
                            name: "rego".into(),
                            constraint: Constraint::parse(">=1.0.0").unwrap(),
                        },
                        engine: Requirement {
                            name: "permguard".into(),
                            constraint: Constraint::parse(">=0.1.0 <0.2.0").unwrap(),
                        },
                    },
                ),
            ]),
            partitions: BTreeMap::from([
                (
                    "app".to_string(),
                    Partition {
                        runtime: "cedar".into(),
                        media_types: vec!["application/vnd.permguard.policy.cedar".into()],
                        schema: false,
                    },
                ),
                (
                    "gateway".to_string(),
                    Partition {
                        runtime: "rego".into(),
                        media_types: vec!["application/vnd.permguard.policy.rego".into()],
                        schema: false,
                    },
                ),
            ]),
            profiles: BTreeMap::from([(
                "default".to_string(),
                Profile {
                    r#type: PROFILE_PDP_V1.into(),
                    partitions: vec!["app".into(), "gateway".into()],
                },
            )]),
        }
    }

    #[test]
    fn round_trips_canonically() {
        let manifest = sample();
        let bytes = manifest.encode();
        assert_eq!(Manifest::decode(&bytes).unwrap(), manifest);
        assert_eq!(bytes, Manifest::decode(&bytes).unwrap().encode());
    }

    #[test]
    fn the_schema_is_fail_closed() {
        let mut manifest = sample();
        manifest.kind = "pipes".into();
        assert!(Manifest::decode(&manifest.encode()).is_err());

        let mut manifest = sample();
        manifest.partitions.get_mut("app").unwrap().runtime = "ghost".into();
        assert!(Manifest::decode(&manifest.encode()).is_err());

        let mut manifest = sample();
        manifest.profiles.get_mut("default").unwrap().partitions = vec!["ghost".into()];
        assert!(Manifest::decode(&manifest.encode()).is_err());

        let mut manifest = sample();
        manifest.profiles.get_mut("default").unwrap().r#type = "acme.custom.v9".into();
        assert!(Manifest::decode(&manifest.encode()).is_err());
    }

    #[test]
    fn the_load_gate_is_fail_closed() {
        let manifest = sample();
        let good = vec![
            ProvidedRuntime {
                language_name: "cedar".into(),
                language_version: Version::parse("4.12.0").unwrap(),
                engine_name: "permguard".into(),
                engine_version: Version::parse("0.1.0").unwrap(),
            },
            ProvidedRuntime {
                language_name: "rego".into(),
                language_version: Version::parse("1.0.0").unwrap(),
                engine_name: "permguard".into(),
                engine_version: Version::parse("0.1.0").unwrap(),
            },
        ];
        assert!(check_load_gate(&manifest, &good).is_ok());

        // Engine outside the range: refused.
        let mut old = good.clone();
        old[0].engine_version = Version::parse("0.2.0").unwrap();
        assert!(check_load_gate(&manifest, &old).is_err());

        // Missing language plugin: refused.
        assert!(check_load_gate(&manifest, &good[..1]).is_err());
    }
}
