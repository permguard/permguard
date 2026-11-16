// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! What a partition may hold: the registry every language describes its artifacts in
//! (`permguard-language-core`), and the catalogue of the artifact types this build carries.

pub use permguard_language_core::artifact::*;

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

/// The registered names, for a message that has to list them.
pub fn registered() -> String {
    let mut names: Vec<&str> = artifact_types()
        .into_iter()
        .map(ArtifactType::name)
        .collect();
    names.sort_unstable();

    names.join(", ")
}

/// What this build offers the manifest's artifact gate.
pub fn provided_artifact_types() -> Vec<permguard_objects::manifest::ProvidedArtifactType> {
    artifact_types()
        .into_iter()
        .map(|held| permguard_objects::manifest::ProvidedArtifactType {
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
        })
        .collect()
}

/// The artifacts of a partition that carries exactly one blob, of one registered type.
///
/// `None` when nothing this build carries registers that name — which is the honest answer, and the
/// reason this takes a name rather than bytes and a promise about them.
pub fn just(type_name: &str, data: &[u8]) -> Option<Artifacts> {
    artifact_type(type_name).map(|artifact| Artifacts::just_of(artifact, data))
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
            let by_media =
                artifact_for_media_type(artifact.media_type()).expect("registered by media type");

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
