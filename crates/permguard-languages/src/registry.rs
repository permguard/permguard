// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The dispatch: from a media type to the language that owns it.
//!
//! This is the layer that knows a catalogue of languages exists — which is
//! why it lives here and not in the object model. The model defines what an
//! object *is*; whether a blob's payload is legal Cedar is a question only
//! whoever holds the languages can answer, and both sides ask it here so
//! they cannot drift: the control plane at ingest, the CLI at build.

use permguard_objects::manifest::{Manifest, ProvidedRuntime};
use permguard_objects::semver::Version;

use crate::lookup::{language_for_media_type, languages};
use crate::role::Language;

/// The registered media types of the built-in languages. Each language owns
/// its own; the model knows only the family prefix and its own manifest.
pub const MEDIA_TYPE_POLICY_CEDAR: &str = "application/vnd.permguard.policy.cedar";
pub const MEDIA_TYPE_SCHEMA_CEDAR: &str = "application/vnd.permguard.schema.cedar";
pub const MEDIA_TYPE_POLICY_REGO: &str = "application/vnd.permguard.policy.rego";
pub const MEDIA_TYPE_SCHEMA_REGO: &str = crate::rego::SCHEMA_MEDIA_TYPE;
pub const MEDIA_TYPE_MANIFEST: &str = permguard_objects::manifest::MEDIA_TYPE;

/// The engine identity of this build, for the manifest load gate.
pub const ENGINE_NAME: &str = "permguard";
pub const ENGINE_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Why a blob was refused: a stable code plus the sentence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlobRejected {
    pub code: &'static str,
    pub message: String,
}

impl std::fmt::Display for BlobRejected {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for BlobRejected {}

/// What this build provides to the load gate: its engine plus every
/// language it carries. Fixed at compile time, like the languages.
pub fn provided_runtimes() -> Vec<ProvidedRuntime> {
    let fallback = Version {
        major: 0,
        minor: 0,
        patch: 0,
    };
    let engine_version = Version::parse(ENGINE_VERSION).unwrap_or(fallback);
    languages()
        .iter()
        .map(|language| ProvidedRuntime {
            language_name: language.name().to_owned(),
            language_version: Version::parse(language.language_version()).unwrap_or(fallback),
            engine_name: ENGINE_NAME.to_owned(),
            engine_version,
        })
        .collect()
}

/// Everything a manifest must satisfy before this build will serve it, in one call.
///
/// Three gates, asked together because forgetting one is the failure this exists to prevent: the
/// runtime gate refuses a ledger whose engine this is not; the input gate refuses a partition
/// whose declared input type nothing here implements, or one written for another runtime; the
/// artifact gate does the same for its declared contents, and refuses a partition missing an
/// artifact its runtime cannot compile without. Three call sites ask this question (the plane at
/// load, the control plane at ingest, the CLI at validate) and each asking it in its own words is
/// how they drift.
pub fn check_manifest(
    manifest: &Manifest,
) -> Result<(), permguard_objects::manifest::ManifestError> {
    check_manifest_with(manifest, &Enabled::everything())
}

/// What a deployment has opted into, among the contracts whose shapes are not yet stable.
///
/// Passed in rather than read from a global, because the languages crate has no configuration and
/// should not grow one: what is provisional is a *deployment's* decision, and this is how that
/// decision reaches the gate that enforces it.
///
/// A set of names rather than a field per runtime. Which runtimes are provisional is
/// [`Language::experimental`]'s answer, so nothing here — and nothing in the configuration types
/// below it — has to be edited when one is added or graduated.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Enabled {
    names: std::collections::BTreeSet<String>,
}

impl Enabled {
    /// Everything this build carries, for a caller with no deployment to consult — the CLI
    /// validating a workspace, and the tests.
    pub fn everything() -> Self {
        Self::from_names(
            languages()
                .iter()
                .filter(|language| language.experimental())
                .map(|language| language.name()),
        )
    }

    /// Nothing provisional, which is what a deployment gets until it says otherwise.
    pub fn stable_only() -> Self {
        Self::default()
    }

    /// The runtimes a deployment named, whatever this build happens to carry.
    pub fn from_names<I, S>(names: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self {
            names: names.into_iter().map(Into::into).collect(),
        }
    }

    /// Whether this deployment will serve the runtime `name`.
    pub fn allows(&self, name: &str) -> bool {
        self.names.contains(name)
    }

    /// Every runtime opted into, in name order.
    pub fn names(&self) -> impl Iterator<Item = &str> {
        self.names.iter().map(String::as_str)
    }
}

/// Refuses an `experimental.<name>` this build does not carry as a provisional runtime.
///
/// A setting nobody reads is worse than a refused one: an operator who misspells the runtime, or
/// names one that has since graduated to stable, gets a deployment that starts and then refuses
/// every ledger of the runtime they thought they had enabled — with a refusal that names the very
/// setting they did set. Reported at startup, where the list of compiled-in languages is known.
pub fn check_opted_in<'a>(named: impl IntoIterator<Item = (&'a str, bool)>) -> Result<(), String> {
    let carried: Vec<&str> = experimental_languages().collect();
    for (name, _) in named {
        if carried.contains(&name) {
            continue;
        }
        let known = if carried.is_empty() {
            "this build carries no experimental runtimes".to_owned()
        } else {
            format!("it carries: {}", carried.join(", "))
        };
        // A stable runtime named here is its own mistake, and a different one: the opt-in does
        // nothing because nothing was ever gated.
        if crate::lookup::language(name).is_some() {
            return Err(format!(
                "`experimental.{name}.enabled` names `{name}`, which is not an experimental \
                 runtime — it is served whether or not it is named here. Remove the setting; {known}"
            ));
        }

        return Err(format!(
            "`experimental.{name}.enabled` names `{name}`, which this build does not carry; {known}"
        ));
    }

    Ok(())
}

/// Every experimental runtime this build carries, by name.
///
/// What a startup check compares a deployment's opt-ins against, so naming one that does not exist
/// is a typo reported at startup rather than a setting that silently does nothing.
pub fn experimental_languages() -> impl Iterator<Item = &'static str> {
    languages()
        .iter()
        .filter(|language| language.experimental())
        .map(|language| language.name())
}

/// The same gate, told what this deployment has opted into.
pub fn check_manifest_with(
    manifest: &Manifest,
    enabled: &Enabled,
) -> Result<(), permguard_objects::manifest::ManifestError> {
    permguard_objects::manifest::check_load_gate(manifest, &provided_runtimes())?;
    permguard_objects::manifest::check_input_contracts(
        manifest,
        &crate::input::provided_input_types(),
    )?;
    permguard_objects::manifest::check_artifact_contracts(
        manifest,
        &crate::artifact::provided_artifact_types(),
    )?;
    check_enabled(manifest, enabled)?;
    check_profile_runtimes(manifest)
}

/// Refuses a ledger that names a contract this deployment has not opted into.
///
/// The language is compiled in either way — a language is a build, not a deployment action — so
/// what this refuses is *serving* the ledger, and it refuses it at load, by name, rather than
/// serving it and having it behave differently after the next upgrade.
fn check_enabled(
    manifest: &Manifest,
    enabled: &Enabled,
) -> Result<(), permguard_objects::manifest::ManifestError> {
    for (name, runtime) in &manifest.runtimes {
        let declared = &runtime.language.name;
        // A language this build does not carry is the load gate's refusal, not this one's: two
        // refusals for one cause would name different settings for the same manifest.
        let Some(language) = crate::lookup::language(declared) else {
            continue;
        };
        if !language.experimental() || enabled.allows(language.name()) {
            continue;
        }

        return Err(permguard_objects::manifest::ManifestError {
            detail: format!(
                "the runtime `{name}` is `{declared}`, and this deployment has not enabled it. \
                 `{declared}`'s wire and replication contracts are provisional, so serving them is \
                 an explicit choice: set `experimental.{declared}.enabled: true`"
            ),
        });
    }

    Ok(())
}

/// Checks that every profile names partitions of the kind its interface can serve.
///
/// The two interfaces are not interchangeable and the difference is not a detail of the payload: a
/// stateless profile answers from the request, a temporal one answers from a durable history it
/// also writes. A profile that named the wrong kind of partition would be discovered by the first
/// caller, as a refusal from an engine — after the ledger had been pushed, mirrored and loaded.
///
/// There is deliberately no conversion in either direction. Deciding a Dogwood policy statelessly
/// means deciding it against an empty history, which is a verdict the policies do not hold; and
/// recording a Cedar partition's request as history means keeping events nothing will ever read.
pub fn check_profile_runtimes(
    manifest: &Manifest,
) -> Result<(), permguard_objects::manifest::ManifestError> {
    use permguard_objects::manifest::{ManifestError, is_temporal_profile};

    let refuse = |detail: String| ManifestError { detail };

    for (name, profile) in &manifest.profiles {
        let temporal = is_temporal_profile(&profile.r#type);
        for partition in &profile.partitions {
            let Some(declared) = manifest.partitions.get(partition) else {
                return Err(refuse(format!(
                    "the profile `{name}` names the partition `{partition}`, which this manifest \
                     does not declare"
                )));
            };
            let Some(runtime) = manifest.runtimes.get(&declared.runtime) else {
                return Err(refuse(format!(
                    "the partition `{partition}` names the runtime `{}`, which this manifest does \
                     not declare",
                    declared.runtime
                )));
            };
            let Some(language) = crate::lookup::language(&runtime.language.name) else {
                // The load gate answers for a language this build does not carry; here there is
                // nothing further to say about it.
                continue;
            };
            if language.is_temporal() == temporal {
                continue;
            }

            return Err(refuse(if temporal {
                format!(
                    "the profile `{name}` is `{}` and names the partition `{partition}`, which \
                     runs `{}` — a runtime that decides from the request alone. A temporal \
                     profile records history and decides against it, and there is no conversion \
                     that would make a stateless partition do so",
                    profile.r#type,
                    language.name()
                )
            } else {
                format!(
                    "the profile `{name}` is `{}` and names the partition `{partition}`, which \
                     runs `{}` — a runtime that decides against a durable history. Deciding it \
                     statelessly would answer against an empty history, which is a verdict its \
                     policies do not hold; name it from a `{}` profile instead",
                    profile.r#type,
                    language.name(),
                    permguard_objects::manifest::PROFILE_PDP_TEMPORAL_V1ALPHA1
                )
            }));
        }
    }

    Ok(())
}

/// Validates one blob against its registered media type — the ingest rule,
/// run by the server on what arrives and by the client on what it builds.
/// An unregistered media type is rejected, fail-closed, never stored as
/// "unknown opaque bytes".
pub fn validate_blob(media_type: &str, data: &[u8]) -> Result<(), BlobRejected> {
    let rejected = |code: &'static str, message: String| BlobRejected { code, message };

    if media_type == MEDIA_TYPE_MANIFEST {
        // The manifest is the model's own object, and the model validates it — then this build
        // says whether it is one it can serve at all, input contracts included. A manifest
        // declaring an input type nobody implements is refused where it is pushed, not discovered
        // by the first caller who addresses that partition.
        let manifest =
            Manifest::decode(data).map_err(|e| rejected("manifest_rejected", e.to_string()))?;

        return check_manifest(&manifest).map_err(|e| rejected("manifest_rejected", e.detail));
    }
    let Some(language) = language_for_media_type(media_type) else {
        return Err(rejected(
            "media_type_unregistered",
            format!("`{media_type}` is not a registered media type"),
        ));
    };
    if language.schema_media_type() == Some(media_type) {
        return language
            .validate_schema(data)
            .map_err(|e| rejected("blob_rejected", e));
    }
    // A registered artifact validates through its own type. Falling through to `validate_policy`
    // would hand an action schema to the policy parser and report the refusal as a broken policy —
    // an error about the wrong file, for a bundle that is in fact well formed.
    if let Some((_, artifact)) = crate::lookup::artifact_for_media_type(media_type) {
        return artifact
            .validate(data)
            .map_err(|e| rejected("blob_rejected", e));
    }

    language
        .validate_policy(data)
        .map_err(|e| rejected("blob_rejected", e))
}

/// The alias a policy source declares, read by its own language — the
/// author's optional handle, which carries identity across renames and
/// never *is* the identity. The ingest path checks the annotation mirrors it.
pub fn declared_alias(media_type: &str, source: &[u8]) -> Option<String> {
    language_for_media_type(media_type)?.declared_alias(source)
}

/// The language a media type belongs to, for callers that need the language
/// itself rather than an answer about one blob.
pub fn language_of(media_type: &str) -> Option<&'static dyn Language> {
    language_for_media_type(media_type)
}

/// The evaluating half of a language named by the manifest, when this build
/// carries one.
///
/// The data plane's entry point into the catalogue: a manifest names a
/// language, and this is what turns that name into something that can decide.
/// A language this build does not carry — or carries without an engine — is
/// `None`, and the load is refused rather than answered best-effort.
pub fn evaluating(language_name: &str) -> Option<&'static dyn crate::evaluate::Evaluating> {
    crate::lookup::language(language_name)?.evaluating()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use std::collections::BTreeMap;

    use permguard_objects::manifest::{
        ArtifactContract, InputContract, Manifest, PROFILE_PDP_NATIVE_V1,
        PROFILE_PDP_TEMPORAL_V1ALPHA1, PROFILE_PDP_V1, Partition, Profile, Requirement, Runtime,
    };
    use permguard_objects::semver::Constraint;

    use super::*;

    /// A manifest with one partition of `language`, named by one profile of `profile_type`.
    fn manifest(language: &str, profile_type: &str) -> Manifest {
        let mut runtimes = BTreeMap::new();
        runtimes.insert(
            language.to_owned(),
            Runtime {
                language: Requirement {
                    name: language.to_owned(),
                    constraint: Constraint::parse(">=1.0.0").expect("a constraint"),
                },
                engine: Requirement {
                    name: ENGINE_NAME.to_owned(),
                    constraint: Constraint::parse(">=0.0.0").expect("a constraint"),
                },
            },
        );
        let mut partitions = BTreeMap::new();
        let dogwood = language == crate::dogwood::NAME;
        partitions.insert(
            "p".to_owned(),
            Partition {
                runtime: language.to_owned(),
                media_types: Vec::new(),
                schema: false,
                artifacts: if dogwood {
                    vec![ArtifactContract {
                        r#type: crate::dogwood::artifacts::ACTION_SCHEMA.to_owned(),
                        required: true,
                    }]
                } else {
                    Vec::new()
                },
                history: None,
                input: Some(InputContract {
                    r#type: if dogwood {
                        crate::input::DOGWOOD_EVENT_V1
                    } else {
                        crate::input::CEDAR_ENTITIES_V1
                    }
                    .to_owned(),
                    required: false,
                }),
            },
        );
        let mut profiles = BTreeMap::new();
        profiles.insert(
            "only".to_owned(),
            Profile {
                r#type: profile_type.to_owned(),
                partitions: vec!["p".to_owned()],
            },
        );

        Manifest {
            kind: "policy".to_owned(),
            name: "gate".to_owned(),
            description: "a manifest for the load gate's own tests".to_owned(),
            author: "Nitro Agility S.r.l.".to_owned(),
            license: "Apache-2.0".to_owned(),
            runtimes,
            partitions,
            profiles,
        }
    }

    #[test]
    fn a_stateless_profile_matches_a_stateless_partition() {
        assert!(check_manifest(&manifest("cedar", PROFILE_PDP_NATIVE_V1)).is_ok());
    }

    /// The rename is a rename, not a second contract: the old spelling still loads.
    #[test]
    fn the_interfaces_former_name_still_loads_and_means_the_same_thing() {
        assert!(
            check_manifest(&manifest("cedar", PROFILE_PDP_V1)).is_ok(),
            "a ledger written before the rename keeps working"
        );
    }

    #[test]
    fn a_temporal_profile_matches_a_temporal_partition() {
        assert!(check_manifest(&manifest("dogwood", PROFILE_PDP_TEMPORAL_V1ALPHA1)).is_ok());
    }

    /// Deciding a Dogwood policy statelessly means deciding it against an empty history.
    #[test]
    fn a_stateless_profile_naming_a_temporal_partition_is_refused_at_the_gate() {
        let refused = check_manifest(&manifest("dogwood", PROFILE_PDP_NATIVE_V1))
            .expect_err("there is no conversion that makes this safe");

        assert!(
            refused.detail.contains("empty history"),
            "{}",
            refused.detail
        );
        assert!(
            refused.detail.contains(PROFILE_PDP_TEMPORAL_V1ALPHA1),
            "the refusal says what to write instead: {}",
            refused.detail
        );
    }

    /// And the other direction: a temporal profile cannot borrow a stateless partition.
    #[test]
    fn a_temporal_profile_naming_a_stateless_partition_is_refused_at_the_gate() {
        let refused = check_manifest(&manifest("cedar", PROFILE_PDP_TEMPORAL_V1ALPHA1))
            .expect_err("a Cedar partition keeps no history");

        assert!(
            refused.detail.contains("decides from the request alone"),
            "{}",
            refused.detail
        );
    }

    /// The legacy spelling is accepted and is *never* what this build writes.
    #[test]
    fn nothing_this_build_generates_carries_the_former_name() {
        assert_eq!(crate::request::INTERFACE, PROFILE_PDP_NATIVE_V1);
        assert_ne!(crate::request::INTERFACE, PROFILE_PDP_V1);
    }

    /// The gate asks each language, rather than consulting a list of names kept beside it.
    #[test]
    fn a_language_declares_whether_it_is_experimental() {
        let carried: Vec<&str> = experimental_languages().collect();
        assert!(
            carried.contains(&crate::dogwood::NAME),
            "Dogwood is provisional: {carried:?}"
        );
        assert!(
            !carried.contains(&"cedar") && !carried.contains(&"rego"),
            "the stable runtimes are not gated: {carried:?}"
        );
        for name in &carried {
            let language = crate::lookup::language(name).expect("it is carried");
            assert!(language.experimental(), "`{name}` answered for itself");
        }
    }

    /// `everything()` is derived from the languages, not written out.
    #[test]
    fn everything_opts_into_exactly_what_this_build_gates() {
        let enabled = Enabled::everything();
        let carried: Vec<&str> = experimental_languages().collect();
        assert_eq!(enabled.names().collect::<Vec<_>>(), carried);
        assert!(Enabled::stable_only().names().next().is_none());
        for name in carried {
            assert!(enabled.allows(name));
            assert!(!Enabled::stable_only().allows(name));
        }
    }

    /// An opt-in naming a runtime this build does not gate is a typo, and typos are reported.
    #[test]
    fn naming_a_runtime_this_build_does_not_gate_is_refused() {
        check_opted_in([(crate::dogwood::NAME, true)]).expect("a runtime this build gates");

        let refused = check_opted_in([("dogwoood", true)]).expect_err("a misspelling");
        assert!(refused.contains("dogwoood"), "{refused}");
        assert!(
            refused.contains("does not carry"),
            "the refusal says what is wrong: {refused}"
        );

        // A stable runtime named here is a different mistake: the opt-in buys nothing, because
        // nothing was ever gated. Saying so beats a refusal that reads as "no such language".
        let stable = check_opted_in([("cedar", true)]).expect_err("cedar is not gated");
        assert!(stable.contains("not an experimental runtime"), "{stable}");
    }
}
