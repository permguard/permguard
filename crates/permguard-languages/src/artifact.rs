// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! What a partition may hold, as a registry rather than a pair of media types.
//!
//! # Why one schema was never going to be enough
//!
//! A partition used to be "policies, and at most one schema", and the manifest said so with
//! `schema: bool`. That held while every runtime had one optional schema. It stops holding the
//! moment a runtime needs several *different* fixed artifacts — a required action schema, an
//! optional event schema, a macro library, provider declarations and the provider programs those
//! declarations name — because "is there a schema" cannot distinguish them, and neither can a file
//! extension: two of those are `.dw`, the same extension as a policy.
//!
//! The alternative to a registry is a switch on file names somewhere in the CLI's walk and another
//! one in the plane's loader, which is two places to disagree about what a ledger holds.
//!
//! # What a registered artifact type fixes
//!
//! Everything an author cannot choose: which runtime owns it, what part it plays, how many of it a
//! partition may hold, which extensions carry it, the canonical file name where an extension alone
//! is ambiguous, and how one blob is validated. A manifest names the type; the registry answers
//! the rest. An author who could redefine cardinality could declare two action schemas, and
//! nothing downstream would know which one a policy was validated against.

use crate::role::Language;

/// What part an artifact plays in a partition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArtifactRole {
    /// A rule the engine evaluates. Carries a policy identity and is cited by a decision.
    Policy,
    /// A contract other artifacts and requests are checked against.
    Schema,
    /// Neither: library or declaration material the runtime reads while compiling.
    Support,
}

/// How many of one type a partition may hold.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cardinality {
    /// Exactly one, always.
    One,
    /// At most one.
    ZeroOrOne,
    /// Any number, including none.
    Many,
}

/// One registered artifact type.
///
/// The unit a manifest names and the registry describes. Implemented by the language that owns it,
/// so a runtime's artifacts arrive with the runtime rather than being wired in beside it.
pub trait ArtifactType: Send + Sync {
    /// The registered name, e.g. `permguard.dogwood.action-schema.v1`.
    fn name(&self) -> &'static str;

    /// The media type this artifact is stored under.
    fn media_type(&self) -> &'static str;

    /// The language that owns it. A partition may only declare artifacts of its own runtime.
    fn runtime(&self) -> &'static str;

    /// Policy, schema or support.
    fn role(&self) -> ArtifactRole;

    /// What it is *within* that role — `action-schema`, `event-schema`, `macros`,
    /// `provider-declarations`, `provider-program`. Two schemas of one runtime are told apart by
    /// this and by nothing else.
    fn semantic_role(&self) -> &'static str;

    /// The file extensions an author writes it in.
    fn extensions(&self) -> &'static [&'static str];

    /// The one file name this type is authored under, where its extension is shared.
    ///
    /// Dogwood policies and its macro library are both `.dw`. The registry reserves `macros.dw`
    /// for the library so the walk stays a lookup instead of becoming a guess; anything else with
    /// that extension is a policy.
    fn canonical_filename(&self) -> Option<&'static str> {
        None
    }

    /// How many a partition may hold.
    fn cardinality(&self) -> Cardinality;

    /// Whether a partition of this runtime must carry one, when it declares no contract of its
    /// own. A manifest may require an otherwise optional artifact; it may not excuse a required
    /// one.
    fn required_by_default(&self) -> bool {
        false
    }

    /// Validates one blob of this type on its own.
    ///
    /// Per-blob only: whether the *set* holds together is the language's question, because that is
    /// where an action schema, an event schema and a policy meet.
    fn validate(&self, bytes: &[u8]) -> Result<(), String>;
}

/// Every artifact type this build carries, in a fixed order.
///
/// Collected from the languages rather than listed here: a language that gains an artifact gains
/// it everywhere at once, and there is no second list to forget.
pub fn artifact_types() -> Vec<&'static dyn ArtifactType> {
    crate::lookup::languages()
        .iter()
        .flat_map(|language| language.artifacts().iter().copied())
        .collect()
}

/// The artifact type of that name, when this build carries one.
pub fn artifact_type(name: &str) -> Option<&'static dyn ArtifactType> {
    artifact_types()
        .into_iter()
        .find(|held| held.name() == name)
}

/// The artifact type stored under a media type.
pub fn artifact_for_media_type(media_type: &str) -> Option<&'static dyn ArtifactType> {
    artifact_types()
        .into_iter()
        .find(|held| held.media_type() == media_type)
}

/// The artifacts one language owns.
pub fn artifacts_of(language: &dyn Language) -> &'static [&'static dyn ArtifactType] {
    language.artifacts()
}

/// The registered names, for a message that has to list them.
pub fn registered() -> String {
    let mut names: Vec<&str> = artifact_types().into_iter().map(ArtifactType::name).collect();
    names.sort_unstable();

    names.join(", ")
}

/// What this build offers the manifest's artifact gate.
pub fn provided_artifact_types() -> Vec<permguard_objects::manifest::ProvidedArtifactType> {
    artifact_types()
        .into_iter()
        .map(
            |held| permguard_objects::manifest::ProvidedArtifactType {
                name: held.name().to_owned(),
                language: held.runtime().to_owned(),
                cardinality: match held.cardinality() {
                    Cardinality::One => permguard_objects::manifest::ArtifactCardinality::One,
                    Cardinality::ZeroOrOne => {
                        permguard_objects::manifest::ArtifactCardinality::ZeroOrOne
                    }
                    Cardinality::Many => permguard_objects::manifest::ArtifactCardinality::Many,
                },
                required_by_default: held.required_by_default(),
            },
        )
        .collect()
}

/// Which artifact type an authored file is, by name and extension.
///
/// The one place that decision is made. A canonical file name wins over a shared extension, which
/// is what lets `macros.dw` and `policy.dw` live in one directory without the walker knowing that
/// Dogwood exists.
pub fn classify<'a>(
    artifacts: &'a [&'static dyn ArtifactType],
    file_name: &str,
) -> Option<&'a &'static dyn ArtifactType> {
    let extension = file_name.rsplit('.').next()?;

    artifacts
        .iter()
        .find(|held| held.canonical_filename() == Some(file_name))
        .or_else(|| {
            artifacts.iter().find(|held| {
                held.canonical_filename().is_none() && held.extensions().contains(&extension)
            })
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_registered_artifact_is_owned_by_a_language_this_build_carries() {
        for artifact in artifact_types() {
            assert!(
                crate::lookup::language(artifact.runtime()).is_some(),
                "`{}` names the runtime `{}`, which this build does not carry",
                artifact.name(),
                artifact.runtime()
            );
            assert!(!artifact.name().is_empty());
            assert!(!artifact.semantic_role().is_empty());
            assert!(
                !artifact.extensions().is_empty(),
                "`{}` is authored in no extension",
                artifact.name()
            );
        }
    }

    #[test]
    fn a_registered_name_and_media_type_resolve_to_the_same_artifact() {
        for artifact in artifact_types() {
            let by_name = artifact_type(artifact.name()).expect("registered by name");
            let by_media = artifact_for_media_type(artifact.media_type())
                .expect("registered by media type");

            assert_eq!(by_name.name(), by_media.name());
        }
    }

    /// Two artifacts of one runtime may share an extension only if all but one name a file.
    ///
    /// Otherwise the walk has no way to tell them apart, and the ledger's contents would depend on
    /// which one the iteration happened to reach first.
    #[test]
    fn a_shared_extension_is_disambiguated_by_a_canonical_filename() {
        for language in crate::lookup::languages() {
            let owned = language.artifacts();
            for (at, artifact) in owned.iter().enumerate() {
                for other in owned.iter().skip(at + 1) {
                    let shares = artifact
                        .extensions()
                        .iter()
                        .any(|extension| other.extensions().contains(extension));
                    if shares {
                        assert!(
                            artifact.canonical_filename().is_some()
                                || other.canonical_filename().is_some(),
                            "`{}` and `{}` share an extension and neither reserves a file name",
                            artifact.name(),
                            other.name()
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn a_name_nobody_registered_is_not_an_artifact() {
        assert!(artifact_type("acme.whatever.v1").is_none());
        assert!(artifact_for_media_type("application/vnd.acme.thing").is_none());
    }
}
