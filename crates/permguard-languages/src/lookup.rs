// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! Which languages this build carries, and how to find one.
//!
//! Fixed at compile time on purpose: a language is a build, not a deployment
//! action, so what interprets policy is exactly what was reviewed, signed
//! and shipped. The concrete languages are private to the crate — they are
//! reached through the roles, never by name.

use crate::role::Language;
use crate::{cedar, dogwood, rego};

/// Every language this build carries. Fixed at compile time, on purpose.
///
/// Dogwood is compiled in like the others. Whether a *ledger* may use it is a separate question,
/// answered at runtime by `experimental.dogwood.enabled`: a language is a build, and gating the
/// build would mean two binaries where the feature flag is supposed to be one setting.
pub fn languages() -> &'static [&'static dyn Language] {
    static CEDAR: cedar::Cedar = cedar::Cedar;
    static DOGWOOD: dogwood::Dogwood = dogwood::Dogwood;
    static REGO: rego::Rego = rego::Rego;
    static ALL: [&'static dyn Language; 3] = [&CEDAR, &DOGWOOD, &REGO];
    &ALL
}

/// Finds a language by name.
pub fn language(name: &str) -> Option<&'static dyn Language> {
    languages().iter().copied().find(|p| p.name() == name)
}

/// Finds the language that owns a media type — policy, legacy schema, or registered artifact.
///
/// The artifact arm is not a convenience: a runtime that describes its contents as typed artifacts
/// answers `None` to [`Language::schema_media_type`] by that method's own contract, so a lookup
/// asking only the legacy pair concludes that the runtime's own action schema belongs to no
/// language — and `validate_blob` then refuses to store what the CLI just built.
pub fn language_for_media_type(media_type: &str) -> Option<&'static dyn Language> {
    languages().iter().copied().find(|p| {
        p.policy_media_type() == media_type
            || p.schema_media_type() == Some(media_type)
            || p.artifacts()
                .iter()
                .any(|held| held.media_type() == media_type)
    })
}

/// Finds the registered artifact type a media type names, with the language that owns it.
pub fn artifact_for_media_type(
    media_type: &str,
) -> Option<(
    &'static dyn Language,
    &'static dyn crate::artifact::ArtifactType,
)> {
    languages().iter().copied().find_map(|language| {
        language
            .artifacts()
            .iter()
            .copied()
            .find(|held| held.media_type() == media_type)
            .map(|held| (language, held))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_registry_carries_every_language_this_build_ships() {
        assert!(language("cedar").is_some());
        assert!(language("dogwood").is_some());
        assert!(language("rego").is_some());
        assert!(language("prolog").is_none());
        assert!(language_for_media_type("application/vnd.permguard.policy.cedar").is_some());
        assert!(language_for_media_type("application/vnd.permguard.policy.rego").is_some());
        assert!(language_for_media_type("application/vnd.permguard.schema.cedar").is_some());
    }
}

#[cfg(test)]
mod role_tests {
    use super::*;

    #[test]
    fn every_language_answers_the_base_role() {
        for language in languages() {
            assert!(!language.name().is_empty());
            assert!(!language.language_version().is_empty());
            assert!(
                language
                    .policy_media_type()
                    .starts_with("application/vnd.permguard.policy.")
            );
        }
    }

    #[test]
    fn the_authoring_half_is_asked_for_never_assumed() {
        // Both built-in languages carry it today; what matters is that a
        // caller has to ask — a build without the authoring half answers
        // `None` and the caller refuses, instead of failing at a call site.
        for language in languages() {
            let authoring = language.authoring().expect("the built-ins author");
            assert!(!authoring.file_extensions().is_empty());
        }
    }
}
