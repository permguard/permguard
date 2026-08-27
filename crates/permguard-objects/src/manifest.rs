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
    /// The one kind of request-supplied input this partition accepts, when it
    /// accepts any. A partition that declares none is addressed by nobody.
    pub input: Option<InputContract>,
}

/// What a partition accepts as its own request-supplied input.
///
/// # Why the manifest decides this and not the caller
///
/// A request may carry data a partition reads — a Cedar entity store, a Rego document. What that
/// data *is* cannot be a field the caller picks, or a caller would be choosing which parser runs
/// over bytes it also supplies. So the ledger declares it, once, per partition: the type names a
/// registered contract, the consumer implements it, and a request's own `type` is an assertion
/// checked against this one rather than a selector.
///
/// `required` is the other half. A partition whose rules only mean something with data — an entity
/// store the policies traverse — is misread, not merely unhelpful, when the data is absent: the
/// request would be decided against an empty graph and denied for the wrong reason. Declaring it
/// required turns that into a refusal naming the partition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InputContract {
    /// The registered input type, e.g. `permguard.cedar.entities.v1`.
    pub r#type: String,
    /// Whether a request must address this partition.
    pub required: bool,
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
const PARTITION_INPUT: i64 = 4;
const INPUT_TYPE: i64 = 1;
const INPUT_REQUIRED: i64 = 2;
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
                        Value::Map(
                            vec![
                                (Value::Int(PARTITION_RUNTIME), text(&partition.runtime)),
                                (
                                    Value::Int(PARTITION_MEDIA_TYPES),
                                    Value::Array(
                                        partition.media_types.iter().map(|m| text(m)).collect(),
                                    ),
                                ),
                                (Value::Int(PARTITION_SCHEMA), Value::Bool(partition.schema)),
                            ]
                            .into_iter()
                            // Absent when the partition accepts no input, so a ledger that
                            // declares none encodes exactly as it did before the field existed.
                            .chain(partition.input.iter().map(|input| {
                                (
                                    Value::Int(PARTITION_INPUT),
                                    Value::Map(vec![
                                        (Value::Int(INPUT_TYPE), text(&input.r#type)),
                                        (Value::Int(INPUT_REQUIRED), Value::Bool(input.required)),
                                    ]),
                                )
                            }))
                            .collect(),
                        ),
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

        only_known(
            &value,
            "the manifest",
            &[KEY_METADATA, KEY_RUNTIMES, KEY_PARTITIONS, KEY_PROFILES],
        )?;
        let metadata = only_known(
            need(pairs, KEY_METADATA, "metadata")?,
            "metadata",
            &[
                META_KIND,
                META_NAME,
                META_DESCRIPTION,
                META_AUTHOR,
                META_LICENSE,
            ],
        )?;
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
            let runtime = only_known(value, "a runtime", &[RUNTIME_LANGUAGE, RUNTIME_ENGINE])?;
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
            let partition = only_known(
                value,
                "a partition",
                &[
                    PARTITION_RUNTIME,
                    PARTITION_MEDIA_TYPES,
                    PARTITION_SCHEMA,
                    PARTITION_INPUT,
                ],
            )?;
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
            let input = match partition
                .iter()
                .find(|(key, _)| *key == Value::Int(PARTITION_INPUT))
            {
                None => None,
                Some((_, value)) => {
                    let pairs =
                        only_known(value, "partition.input", &[INPUT_TYPE, INPUT_REQUIRED])?;
                    let required = match need(pairs, INPUT_REQUIRED, "partition.input.required")? {
                        Value::Bool(required) => *required,
                        _ => return Err(bad("partition.input.required must be a boolean")),
                    };

                    Some(InputContract {
                        r#type: get_text(pairs, INPUT_TYPE, "partition.input.type")?,
                        required,
                    })
                }
            };
            manifest.partitions.insert(
                name.clone(),
                Partition {
                    runtime,
                    media_types,
                    schema,
                    input,
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
            let profile = only_known(value, "a profile", &[PROFILE_TYPE, PROFILE_PARTITIONS])?;
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
            grammar::validate_entry_name(name).map_err(|e| bad(format!("profile `{name}`: {e}")))?;
            // A profile is a contract offered *across* partitions. One that names none offers
            // nothing: every request under it would find nothing to ask, and the answer would be
            // a deny with no policy behind it — indistinguishable from a policy refusing, and
            // impossible to debug. Refused where it is written instead.
            if partitions.is_empty() {
                return Err(bad(format!(
                    "profile `{name}` names no partitions: a profile is the contract some \
                     partitions answer, and one that names none can only ever deny"
                )));
            }
            let mut named = std::collections::BTreeSet::new();
            for partition in &partitions {
                if !manifest.partitions.contains_key(partition) {
                    return Err(bad(format!(
                        "profile `{name}` names the partition `{partition}`, which is not declared"
                    )));
                }
                // Twice is not twice as much: the partition would be compiled once and asked
                // twice, its verdict counted twice, and its policies cited twice in the reason.
                // Nobody means that, so it is a mistake and not a feature.
                if !named.insert(partition.clone()) {
                    return Err(bad(format!(
                        "profile `{name}` names the partition `{partition}` twice: it would be \
                         asked twice and cited twice, which is nobody's intent"
                    )));
                }
            }
            manifest
                .profiles
                .insert(name.clone(), Profile { r#type, partitions });
        }
        // A ledger nobody can ask is a ledger that will be pushed, mirrored, compiled and then
        // refuse every request with `profile_unknown`. The two lists above are already required
        // to be non-empty; this is the third.
        if manifest.profiles.is_empty() {
            return Err(bad(
                "a manifest declares at least one profile: a ledger with none can be stored and \
                 never asked",
            ));
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

/// What one consumer implements of the partition-input registry: a type's
/// name and the runtime that can read it.
///
/// The mirror of [`ProvidedRuntime`], for the same reason: the model defines what a manifest *is*
/// and knows no language, so the catalogue of input types is offered to it by whoever holds the
/// languages.
#[derive(Debug, Clone)]
pub struct ProvidedInputType {
    pub name: String,
    /// The language of the runtime that reads this input, e.g. `cedar`.
    pub language: String,
}

/// The second half of the load gate: every partition input contract must name a type this
/// consumer implements, and one its own runtime can read.
///
/// Fail-closed, and for the same reason as the runtime gate. A type nobody implements is a
/// partition whose declared input would be accepted from a caller and then read by nothing; a type
/// belonging to another runtime is a Rego document handed to Cedar. Both are refusals at load, not
/// surprises at the first request that carries data.
pub fn check_input_contracts(
    manifest: &Manifest,
    provided: &[ProvidedInputType],
) -> Result<(), ManifestError> {
    for (name, partition) in &manifest.partitions {
        let Some(input) = &partition.input else {
            continue;
        };
        let offered = provided
            .iter()
            .find(|held| held.name == input.r#type)
            .ok_or_else(|| {
                let known: Vec<&str> = provided.iter().map(|held| held.name.as_str()).collect();
                bad(format!(
                    "partition `{name}` declares the input type `{}`, which this build does not \
                     implement (it implements: {})",
                    input.r#type,
                    known.join(", ")
                ))
            })?;
        // The partition names a runtime key; what the input type is written for is a language.
        let runtime = manifest.runtimes.get(&partition.runtime).ok_or_else(|| {
            bad(format!(
                "partition `{name}` names the runtime `{}`, which is not declared",
                partition.runtime
            ))
        })?;
        if offered.language != runtime.language.name {
            return Err(bad(format!(
                "partition `{name}` runs `{}` and declares the input type `{}`, which is written \
                 for `{}`: an input is read by one runtime, and no other can read it",
                runtime.language.name, input.r#type, offered.language
            )));
        }
    }

    Ok(())
}

fn decode_requirement(value: &Value) -> Result<Requirement, ManifestError> {
    let pairs = only_known(value, "a requirement", &[REQ_NAME, REQ_CONSTRAINT])?;
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

/// The map, and nothing in it this build does not know.
///
/// # Why an unknown key is a refusal
///
/// This decoder documents itself as fail-closed on anything the schema does not list, and it was
/// not: it picked the keys it knew and let the rest go by. A manifest carrying a key this build
/// cannot read is a manifest written for a Permguard that is not this one — and the thing it says
/// might be *`required: true`*, or a partition constraint, or anything else whose absence changes
/// what is enforced. Reading the rest of it and serving the result is the failure mode this whole
/// object model exists to prevent.
///
/// Forward compatibility is not lost by this; it is *relocated*, to where the manifest already
/// puts it. A ledger that needs a newer reader says so in `runtimes.<key>.engine`, and the load
/// gate refuses an engine outside that range by name. That is a diagnosis. Silently ignoring a
/// field is not.
fn only_known<'a>(
    value: &'a Value,
    what: &str,
    known: &[i64],
) -> Result<&'a [(Value, Value)], ManifestError> {
    let pairs = as_map(value, what)?;
    for (key, _) in pairs {
        let Value::Int(key) = key else {
            return Err(bad(format!("{what} keys must be integers")));
        };
        if !known.contains(key) {
            return Err(bad(format!(
                "{what} carries the key {key}, which this build does not know: the manifest was \
                 written for another Permguard, and reading the rest of it would be deciding \
                 against a model nobody agreed to"
            )));
        }
    }

    Ok(pairs)
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
                        input: None,
                    },
                ),
                (
                    "gateway".to_string(),
                    Partition {
                        runtime: "rego".into(),
                        media_types: vec!["application/vnd.permguard.policy.rego".into()],
                        schema: false,
                        input: None,
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

#[cfg(test)]
mod input_contract_tests {
    use super::*;

    fn manifest(runtime: &str, input: Option<InputContract>) -> Manifest {
        let mut built = Manifest {
            kind: KIND_POLICY.to_owned(),
            name: "l".to_owned(),
            ..Manifest::default()
        };
        built.runtimes.insert(
            runtime.to_owned(),
            Runtime {
                language: Requirement {
                    name: runtime.to_owned(),
                    constraint: Constraint::parse(">=1.0.0").expect("a constraint"),
                },
                engine: Requirement {
                    name: "permguard".to_owned(),
                    constraint: Constraint::parse(">=0.1.0").expect("a constraint"),
                },
            },
        );
        built.partitions.insert(
            "p".to_owned(),
            Partition {
                runtime: runtime.to_owned(),
                media_types: vec!["application/vnd.permguard.policy.cedar".to_owned()],
                schema: false,
                input,
            },
        );
        built.profiles.insert(
            "default".to_owned(),
            Profile {
                r#type: PROFILE_PDP_V1.to_owned(),
                partitions: vec!["p".to_owned()],
            },
        );

        built
    }

    fn provided() -> Vec<ProvidedInputType> {
        vec![
            ProvidedInputType {
                name: "permguard.cedar.entities.v1".to_owned(),
                language: "cedar".to_owned(),
            },
            ProvidedInputType {
                name: "permguard.rego.data.v1".to_owned(),
                language: "rego".to_owned(),
            },
        ]
    }

    #[test]
    fn a_partition_that_declares_no_input_passes_the_gate() {
        assert!(check_input_contracts(&manifest("cedar", None), &provided()).is_ok());
    }

    #[test]
    fn an_input_type_this_build_does_not_implement_makes_the_manifest_invalid() {
        let refused = check_input_contracts(
            &manifest(
                "cedar",
                Some(InputContract {
                    r#type: "acme.entities.v1".to_owned(),
                    required: false,
                }),
            ),
            &provided(),
        )
        .expect_err("nobody implements it");

        assert!(refused.detail.contains("acme.entities.v1"), "{refused}");
    }

    #[test]
    fn an_input_type_written_for_another_runtime_makes_the_manifest_invalid() {
        let refused = check_input_contracts(
            &manifest(
                "cedar",
                Some(InputContract {
                    r#type: "permguard.rego.data.v1".to_owned(),
                    required: false,
                }),
            ),
            &provided(),
        )
        .expect_err("Cedar cannot read a Rego document");

        assert!(refused.detail.contains("one runtime"), "{refused}");
    }

    #[test]
    fn an_input_contract_survives_the_canonical_encoding() {
        let built = manifest(
            "cedar",
            Some(InputContract {
                r#type: "permguard.cedar.entities.v1".to_owned(),
                required: true,
            }),
        );
        let decoded = Manifest::decode(&built.encode()).expect("it round-trips");

        assert_eq!(decoded.partitions["p"].input, built.partitions["p"].input);
        // And a manifest that declares none still encodes as one that never had the field.
        let plain = manifest("cedar", None);
        assert_eq!(
            Manifest::decode(&plain.encode())
                .expect("it round-trips")
                .partitions["p"]
                .input,
            None
        );
    }
}

#[cfg(test)]
mod profile_tests {
    use super::*;

    fn manifest(profiles: Vec<(&str, Vec<&str>)>) -> Manifest {
        let mut built = Manifest {
            kind: KIND_POLICY.to_owned(),
            name: "l".to_owned(),
            ..Manifest::default()
        };
        built.runtimes.insert(
            "cedar".to_owned(),
            Runtime {
                language: Requirement {
                    name: "cedar".to_owned(),
                    constraint: Constraint::parse(">=1.0.0").expect("a constraint"),
                },
                engine: Requirement {
                    name: "permguard".to_owned(),
                    constraint: Constraint::parse(">=0.1.0").expect("a constraint"),
                },
            },
        );
        for name in ["a", "b"] {
            built.partitions.insert(
                name.to_owned(),
                Partition {
                    runtime: "cedar".to_owned(),
                    media_types: vec!["application/vnd.permguard.policy.cedar".to_owned()],
                    schema: false,
                    input: None,
                },
            );
        }
        for (name, partitions) in profiles {
            built.profiles.insert(
                name.to_owned(),
                Profile {
                    r#type: PROFILE_PDP_V1.to_owned(),
                    partitions: partitions.into_iter().map(ToOwned::to_owned).collect(),
                },
            );
        }

        built
    }

    fn decode(manifest: &Manifest) -> Result<Manifest, ManifestError> {
        Manifest::decode(&manifest.encode())
    }

    #[test]
    fn a_profile_across_one_or_more_partitions_is_accepted() {
        assert!(decode(&manifest(vec![("admin", vec!["a"])])).is_ok());
        assert!(decode(&manifest(vec![("admin", vec!["a", "b"])])).is_ok());
    }

    /// A profile that names no partitions can only ever deny, with nothing to cite.
    #[test]
    fn a_profile_that_names_no_partitions_is_refused() {
        let refused = decode(&manifest(vec![("empty", vec![])])).expect_err("it asks nothing");

        assert!(refused.detail.contains("names no partitions"), "{refused}");
    }

    /// Named twice, a partition is asked twice and cited twice. Nobody means that.
    #[test]
    fn a_profile_that_names_a_partition_twice_is_refused() {
        let refused =
            decode(&manifest(vec![("admin", vec!["a", "a"])])).expect_err("once is once");

        assert!(refused.detail.contains("twice"), "{refused}");
    }

    #[test]
    fn a_manifest_with_no_profiles_at_all_is_refused() {
        let refused = decode(&manifest(vec![])).expect_err("nobody could ask it anything");

        assert!(refused.detail.contains("at least one profile"), "{refused}");
    }

    #[test]
    fn a_profile_name_follows_the_same_grammar_as_everything_else() {
        let refused =
            decode(&manifest(vec![("Not A Name", vec!["a"])])).expect_err("that is not a name");

        assert!(refused.detail.contains("profile"), "{refused}");
    }

    /// A key this build does not know is a manifest written for another Permguard.
    ///
    /// The decoder said it was fail-closed on anything the schema does not list, and it was not:
    /// it picked the keys it knew and let the rest go by. What it let by might have been the one
    /// that says a partition's input is mandatory.
    #[test]
    fn a_key_this_build_does_not_know_is_refused_rather_than_skipped() {
        let mut encoded =
            crate::cbor::decode_canonical(&manifest(vec![("admin", vec!["a"])]).encode())
                .expect("it decodes");
        let crate::cbor::Value::Map(pairs) = &mut encoded else {
            panic!("a manifest is a map")
        };
        // The encoder sorts and canonicalises, so this is a well-formed manifest blob that
        // simply carries one key more than this build knows.
        pairs.push((crate::cbor::Value::Int(99), crate::cbor::Value::Bool(true)));

        let refused =
            Manifest::decode(&crate::cbor::encode(&encoded)).expect_err("nobody here knows key 99");

        assert!(refused.detail.contains("99"), "{refused}");
    }
}
