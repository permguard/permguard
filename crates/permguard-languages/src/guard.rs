// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The panic boundary around every in-process engine entry.
//!
//! The execution contract requires `catch_unwind` around every place an engine is entered, not
//! only around evaluation: a parser that comes apart validating a pushed policy, a compiler that
//! comes apart loading a ledger, or a schema check that comes apart on a request must each end as
//! that operation's refusal — never as a crashed CLI, a `500` carrying the engine's own words, or
//! an occurrence left durable and unapplied.
//!
//! [`Guarded`] wraps a built-in language so every caller that reaches it through the registry gets
//! the boundary on validation, extraction and compilation. Evaluation has its own, per job, in
//! [`crate::evaluate::evaluate_all`]; the input check and the temporal entries are wrapped with
//! [`contained`] where they are called, because each of those refuses in its own terms.
//!
//! A panic's own message is never part of a refusal: an engine's words can carry policy text or
//! tenant data. It is returned to the caller, which keeps it as internal detail at most.

use crate::artifact::Artifacts;
use crate::evaluate::{Evaluating, Evaluator, StoredPolicy};
use crate::role::{Authoring, ExtractedPolicy, Language};

/// Runs `work`, and answers what it returned, or what its panic said.
pub fn contained<T>(work: impl FnOnce() -> T) -> Result<T, String> {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(work))
        .map_err(|panic| panic_message(panic.as_ref()))
}

/// What a panic said, when it said it as text; a fixed sentence otherwise.
pub fn panic_message(panic: &(dyn std::any::Any + Send)) -> String {
    panic
        .downcast_ref::<&str>()
        .map(|message| (*message).to_owned())
        .or_else(|| panic.downcast_ref::<String>().cloned())
        .unwrap_or_else(|| "a panic that carried no message".to_owned())
}

/// Reports a panic by where it happened, never by what it said.
///
/// The default hook writes every panic's message to standard error, caught or not — and a policy
/// engine's panic message can carry policy text or tenant data, which would reach the container's
/// logs past their field classification. A server installs this first thing; the location is
/// what a maintainer needs to find the fault.
pub fn report_panics_without_their_words() {
    std::panic::set_hook(Box::new(|info| {
        let location = info
            .location()
            .map(|at| format!("{}:{}", at.file(), at.line()))
            .unwrap_or_else(|| "an unknown location".to_owned());
        eprintln!(
            "a panic at {location}; its message is withheld, because it can carry policy text or \
             tenant data"
        );
    }));
}

/// A built-in language, every engine entry of which is inside the panic boundary.
pub struct Guarded<L: Language + 'static>(pub L);

impl<L: Language + 'static> Guarded<L> {
    fn came_apart(&self, doing: &str) -> String {
        format!(
            "the `{}` engine came apart {doing}; nothing it was given was accepted",
            self.0.name()
        )
    }
}

/// The schema a floor that came apart demands: a name no artifact has, so nothing satisfies it.
const FLOOR_CAME_APART: &str = "a schema floor that came apart";

impl<L: Language + 'static> Language for Guarded<L> {
    fn name(&self) -> &'static str {
        self.0.name()
    }

    fn language_version(&self) -> &'static str {
        self.0.language_version()
    }

    fn required_schemas(
        &self,
        profile: permguard_core::assurance::AssuranceProfile,
    ) -> &'static [&'static str] {
        // A floor that came apart is no floor at all: demand a schema no partition carries, so
        // the partition is refused rather than served without one.
        contained(|| self.0.required_schemas(profile)).unwrap_or(&[FLOOR_CAME_APART])
    }

    fn isolation_required(&self, profile: permguard_core::assurance::AssuranceProfile) -> bool {
        // A requirement that came apart is kept: isolate rather than run unbounded.
        contained(|| self.0.isolation_required(profile)).unwrap_or(true)
    }

    fn engine(&self) -> crate::descriptor::Engine {
        self.0.engine()
    }

    fn experimental(&self) -> bool {
        self.0.experimental()
    }

    fn policy_media_type(&self) -> &'static str {
        self.0.policy_media_type()
    }

    fn schema_media_type(&self) -> Option<&'static str> {
        self.0.schema_media_type()
    }

    fn artifacts(&self) -> &'static [&'static dyn crate::artifact::ArtifactType] {
        self.0.artifacts()
    }

    fn validate_policy(&self, bytes: &[u8]) -> Result<(), String> {
        contained(|| self.0.validate_policy(bytes))
            .unwrap_or_else(|_| Err(self.came_apart("validating a policy")))
    }

    fn validate_schema(&self, bytes: &[u8]) -> Result<(), String> {
        contained(|| self.0.validate_schema(bytes))
            .unwrap_or_else(|_| Err(self.came_apart("validating a schema")))
    }

    fn validate_set(
        &self,
        policies: &[(&str, &[u8])],
        schema: Option<&[u8]>,
    ) -> Result<(), String> {
        contained(|| self.0.validate_set(policies, schema))
            .unwrap_or_else(|_| Err(self.came_apart("validating a partition")))
    }

    fn validate_bundle(
        &self,
        partition: &str,
        policies: &[(&str, &[u8])],
        artifacts: &std::collections::BTreeMap<String, Vec<u8>>,
        declared: &permguard_objects::manifest::Partition,
    ) -> Result<(), String> {
        contained(|| {
            self.0
                .validate_bundle(partition, policies, artifacts, declared)
        })
        .unwrap_or_else(|_| Err(self.came_apart("validating a partition")))
    }

    /// A source whose alias reading came apart is refused, never read as declaring none: an alias
    /// is identity, and "could not read it" is not "there is none".
    fn declared_alias(&self, source: &[u8]) -> Result<Option<String>, String> {
        contained(|| self.0.declared_alias(source))
            .unwrap_or_else(|_| Err(self.came_apart("reading an alias")))
    }

    fn authoring(&self) -> Option<&dyn Authoring> {
        self.0.authoring().map(|_| self as &dyn Authoring)
    }

    fn is_temporal(&self) -> bool {
        self.0.is_temporal()
    }

    fn guarded(&self) -> bool {
        true
    }

    fn evaluating(&self) -> Option<&dyn Evaluating> {
        self.0.evaluating().map(|_| self as &dyn Evaluating)
    }
}

impl<L: Language + 'static> Authoring for Guarded<L> {
    fn file_extensions(&self) -> &'static [&'static str] {
        self.0
            .authoring()
            .map_or(&[], |authoring| authoring.file_extensions())
    }

    fn schema_file_extensions(&self) -> &'static [&'static str] {
        self.0
            .authoring()
            .map_or(&[], |authoring| authoring.schema_file_extensions())
    }

    fn extract(&self, source: &[u8]) -> Result<Vec<ExtractedPolicy>, String> {
        let Some(authoring) = self.0.authoring() else {
            return Err(format!("`{}` carries no authoring half", self.0.name()));
        };
        contained(|| authoring.extract(source))
            .unwrap_or_else(|_| Err(self.came_apart("splitting a source file")))
    }
}

impl<L: Language + 'static> Evaluating for Guarded<L> {
    fn compile(
        &self,
        policies: &[StoredPolicy],
        artifacts: &Artifacts,
    ) -> Result<Box<dyn Evaluator>, String> {
        let Some(evaluating) = self.0.evaluating() else {
            return Err(format!("`{}` carries no evaluating half", self.0.name()));
        };
        contained(|| evaluating.compile(policies, artifacts))
            .unwrap_or_else(|_| Err(self.came_apart("compiling a partition")))
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;

    /// A language every entry of which panics.
    struct Fragile;

    impl Language for Fragile {
        fn name(&self) -> &'static str {
            "fragile"
        }
        fn language_version(&self) -> &'static str {
            "1.0.0"
        }
        fn engine(&self) -> crate::descriptor::Engine {
            crate::lookup::language("cedar").expect("carried").engine()
        }
        fn policy_media_type(&self) -> &'static str {
            "application/vnd.permguard.policy.fragile"
        }
        fn schema_media_type(&self) -> Option<&'static str> {
            None
        }
        fn validate_policy(&self, _bytes: &[u8]) -> Result<(), String> {
            panic!("the parser came apart over policy text")
        }
        fn declared_alias(&self, _source: &[u8]) -> Result<Option<String>, String> {
            panic!("the alias reader came apart")
        }
        fn authoring(&self) -> Option<&dyn Authoring> {
            Some(self)
        }
        fn evaluating(&self) -> Option<&dyn Evaluating> {
            Some(self)
        }
    }

    impl Authoring for Fragile {
        fn file_extensions(&self) -> &'static [&'static str] {
            &["fragile"]
        }
        fn extract(&self, _source: &[u8]) -> Result<Vec<ExtractedPolicy>, String> {
            panic!("the splitter came apart")
        }
    }

    impl Evaluating for Fragile {
        fn compile(
            &self,
            _policies: &[StoredPolicy],
            _artifacts: &Artifacts,
        ) -> Result<Box<dyn Evaluator>, String> {
            panic!("the compiler came apart over secret policy text")
        }
    }

    /// Every entry through the guard ends as that entry's refusal, never as a panic, and the
    /// refusal never carries the panic's words.
    #[test]
    fn every_guarded_entry_refuses_instead_of_panicking() {
        let guarded = Guarded(Fragile);

        let refused = guarded.validate_policy(b"x").expect_err("refused");
        assert!(
            refused.contains("came apart validating a policy"),
            "{refused}"
        );
        assert!(
            !refused.contains("policy text"),
            "the panic's words stay out: {refused}"
        );
        // A reader that came apart refuses the alias: never read as declaring none.
        let refused = guarded.declared_alias(b"x").expect_err("refused");
        assert!(refused.contains("came apart reading an alias"), "{refused}");
        let authoring = guarded.authoring().expect("it authors");
        assert!(authoring.extract(b"x").is_err());
        let evaluating = guarded.evaluating().expect("it evaluates");
        let refused = evaluating
            .compile(&[], &Artifacts::default())
            .err()
            .expect("refused");
        assert!(!refused.contains("secret"), "{refused}");
    }

    /// The built-ins are reached through the guard, and only through it.
    #[test]
    fn the_registry_hands_out_guarded_languages() {
        for language in crate::lookup::languages() {
            assert!(
                language.guarded(),
                "`{}` is reached unguarded",
                language.name()
            );
        }
        assert!(!Fragile.guarded(), "a bare language says it is bare");
    }
}
