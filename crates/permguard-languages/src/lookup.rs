// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! Which languages this process carries, and how to find one.
//!
//! Fixed before anything reads it, on purpose: a language is a build, not a deployment action, so
//! what interprets policy is exactly what was reviewed, signed and shipped. The concrete languages
//! are private to their packages — they are reached through the roles, never by name.
//!
//! Two ways put a language in the catalogue, and they are one implementation:
//!
//! - this package's features, `cedar`, `rego` and `dogwood`: a build without one does not link
//!   its engine;
//! - [`register`], for an application that links a language package itself and hands its engine
//!   to the Data Plane it embeds.
//!
//! Registration is deterministic and never silent. An engine is registered before the catalogue
//! is first read; from that read on the catalogue is sealed, and a registration is refused. A
//! language the catalogue already holds, by a feature or by an earlier registration, is refused
//! too: nothing is ever replaced. The order is fixed, whatever order engines were registered in.

use std::sync::LazyLock;
#[cfg(feature = "evaluate")]
use std::sync::Mutex;

use crate::role::Language;

/// The order the built-in languages keep in the catalogue; any other follows them, by name.
const ORDER: [&str; 3] = [
    permguard_language_core::names::CEDAR,
    permguard_language_core::names::DOGWOOD,
    permguard_language_core::names::REGO,
];

fn rank(name: &str) -> (usize, &str) {
    (
        ORDER
            .iter()
            .position(|held| *held == name)
            .unwrap_or(ORDER.len()),
        name,
    )
}

/// The engines an application registered, until the catalogue is sealed.
#[cfg(feature = "evaluate")]
struct Pending {
    engines: Vec<permguard_pdp_core::Engine>,
    sealed: bool,
}

#[cfg(feature = "evaluate")]
static PENDING: Mutex<Pending> = Mutex::new(Pending {
    engines: Vec::new(),
    sealed: false,
});

/// Why an engine was not registered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Unregistered {
    /// The catalogue already holds a language of this name, by a feature of the build or by an
    /// earlier registration: nothing is replaced.
    Duplicate(String),
    /// The catalogue was already read: what it held then is what this process decides with.
    Sealed(String),
}

impl std::fmt::Display for Unregistered {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Duplicate(name) => write!(
                formatter,
                "the language `{name}` is already in this process's catalogue, and an engine is \
                 never replaced: register it once, or select it by a feature, not both"
            ),
            Self::Sealed(name) => write!(
                formatter,
                "the engine of `{name}` was registered after this process's catalogue was read: \
                 register every engine before anything is loaded or decided"
            ),
        }
    }
}

impl std::error::Error for Unregistered {}

/// The built-in languages this build's features carry, in the catalogue's order.
fn built_in() -> Vec<&'static dyn Language> {
    let carried: &[&'static dyn Language] = &[
        #[cfg(feature = "cedar")]
        permguard_language_cedar::language(),
        #[cfg(feature = "dogwood")]
        permguard_language_dogwood::language(),
        #[cfg(feature = "rego")]
        permguard_language_rego::language(),
    ];
    carried.to_vec()
}

/// Registers `engine` in this process's catalogue, both halves at once.
///
/// For an application that embeds the Data Plane and links a language package itself. Called
/// before anything is loaded or decided: once the catalogue was read it is sealed. A language
/// already held is refused, whoever put it there.
#[cfg(feature = "evaluate")]
pub fn register(engine: permguard_pdp_core::Engine) -> Result<(), Unregistered> {
    let mut pending = PENDING
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let name = engine.name();
    if pending.sealed {
        return Err(Unregistered::Sealed(name.to_owned()));
    }
    let held = built_in().iter().any(|language| language.name() == name)
        || pending.engines.iter().any(|held| held.name() == name);
    if held {
        return Err(Unregistered::Duplicate(name.to_owned()));
    }
    pending.engines.push(engine);
    Ok(())
}

/// The catalogue, read once: sealed from that read on.
struct Catalogue {
    languages: Vec<&'static dyn Language>,
    #[cfg(feature = "evaluate")]
    evaluators: Vec<(&'static str, &'static dyn permguard_pdp_core::Evaluating)>,
}

static CATALOGUE: LazyLock<Catalogue> = LazyLock::new(|| {
    let mut languages = built_in();
    #[cfg(feature = "evaluate")]
    let mut evaluators: Vec<(&'static str, &'static dyn permguard_pdp_core::Evaluating)> = vec![
        #[cfg(feature = "cedar")]
        (
            permguard_language_cedar::NAME,
            permguard_language_cedar::evaluating(),
        ),
        #[cfg(feature = "dogwood")]
        (
            permguard_language_dogwood::NAME,
            permguard_language_dogwood::evaluating(),
        ),
        #[cfg(feature = "rego")]
        (
            permguard_language_rego::NAME,
            permguard_language_rego::evaluating(),
        ),
    ];
    #[cfg(feature = "evaluate")]
    {
        // Sealed under the same lock a registration takes: an engine is in this read, or refused.
        let mut pending = PENDING
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        pending.sealed = true;
        for engine in &pending.engines {
            languages.push(engine.language());
            evaluators.push((engine.name(), engine.evaluating()));
        }
        evaluators.sort_by(|left, right| rank(left.0).cmp(&rank(right.0)));
    }
    languages.sort_by(|left, right| rank(left.name()).cmp(&rank(right.name())));
    Catalogue {
        languages,
        #[cfg(feature = "evaluate")]
        evaluators,
    }
});

/// Every language this process carries: those the build's features select and those an
/// application registered, in one fixed order. Reading it seals it.
///
/// Dogwood is compiled in like the others. Whether a *ledger* may use it is a separate question,
/// answered at runtime by `experimental.dogwood.enabled`: a language is a build, and gating the
/// build would mean two binaries where the feature flag is supposed to be one setting.
///
/// Each one is reached through [`crate::guard::Guarded`], so every caller — a plane loading a
/// ledger, the control plane validating a push, the CLI building a workspace — enters its engine
/// inside the panic boundary.
pub fn languages() -> &'static [&'static dyn Language] {
    CATALOGUE.languages.as_slice()
}

/// The evaluating half of every language this process carries, by name, in the catalogue's order.
///
/// Only with the `evaluate` feature: a build that validates, as the Control Plane's ingest does,
/// carries no evaluator. Each is behind the same panic boundary as its language.
#[cfg(feature = "evaluate")]
pub fn evaluators() -> &'static [(&'static str, &'static dyn permguard_pdp_core::Evaluating)] {
    CATALOGUE.evaluators.as_slice()
}

/// The evaluating half of the language `name`, when this build carries and evaluates it.
#[cfg(feature = "evaluate")]
pub fn evaluating(name: &str) -> Option<&'static dyn permguard_pdp_core::Evaluating> {
    evaluators()
        .iter()
        .find(|(held, _)| *held == name)
        .map(|(_, evaluating)| *evaluating)
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
    // The tests that name a language run where it is carried; what only they use is idle elsewhere.
    #![cfg_attr(
        not(all(feature = "cedar", feature = "dogwood", feature = "rego")),
        allow(dead_code, unused_imports)
    )]
    use super::*;

    #[cfg(all(feature = "cedar", feature = "dogwood", feature = "rego"))]
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

    /// The built-ins are reached through the guard, and only through it.
    #[test]
    fn the_registry_hands_out_guarded_languages() {
        for language in languages() {
            assert!(
                language.guarded(),
                "`{}` is reached unguarded",
                language.name()
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
