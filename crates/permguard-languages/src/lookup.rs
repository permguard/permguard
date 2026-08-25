// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! Which languages this build carries, and how to find one.
//!
//! Fixed at compile time on purpose: a language is a build, not a deployment
//! action, so what interprets policy is exactly what was reviewed, signed
//! and shipped. The concrete languages are private to the crate — they are
//! reached through the roles, never by name.

use crate::role::Language;
use crate::{cedar, rego};

/// Every language this build carries. Fixed at compile time, on purpose.
pub fn languages() -> &'static [&'static dyn Language] {
    static CEDAR: cedar::Cedar = cedar::Cedar;
    static REGO: rego::Rego = rego::Rego;
    static ALL: [&'static dyn Language; 2] = [&CEDAR, &REGO];
    &ALL
}

/// Finds a language by name.
pub fn language(name: &str) -> Option<&'static dyn Language> {
    languages().iter().copied().find(|p| p.name() == name)
}

/// Finds the language that owns a media type — policy or schema.
pub fn language_for_media_type(media_type: &str) -> Option<&'static dyn Language> {
    languages()
        .iter()
        .copied()
        .find(|p| p.policy_media_type() == media_type || p.schema_media_type() == Some(media_type))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_registry_carries_both_languages() {
        assert!(language("cedar").is_some());
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
