// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The panic boundary around the evaluating half: a compiler that comes apart loading a ledger
//! ends as that load's refusal, never as a crashed plane or a refusal carrying the engine's words.
//! The boundary around every other entry is the language's (`permguard_language_core::guard`).

use permguard_language_core::artifact::Artifacts;
use permguard_language_core::evaluate::StoredPolicy;
use permguard_language_core::guard::{Guarded, contained};
use permguard_language_core::role::Language;

use crate::evaluate::{Evaluating, Evaluator};

impl<L: Language + Evaluating + 'static> Evaluating for Guarded<L> {
    fn compile(
        &self,
        policies: &[StoredPolicy],
        artifacts: &Artifacts,
    ) -> Result<Box<dyn Evaluator>, String> {
        contained(|| self.0.compile(policies, artifacts))
            .unwrap_or_else(|_| Err(self.came_apart("compiling a partition")))
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;

    /// A language whose compiler panics.
    struct Fragile;

    impl Language for Fragile {
        fn name(&self) -> &'static str {
            "fragile"
        }
        fn language_version(&self) -> &'static str {
            "1.0.0"
        }
        fn engine(&self) -> permguard_language_core::descriptor::Engine {
            use permguard_language_core::descriptor::{
                Capabilities, Engine, Isolation, IsolationMode, Locked,
            };

            Engine {
                locked: Locked {
                    name: "fragile-engine",
                    version: "1.0.0",
                    build: "sha256:00",
                },
                capabilities: Capabilities {
                    features: &[],
                    extensions: &[],
                    clock: false,
                    randomness: false,
                    io: false,
                },
                limits: &[],
                isolation: Isolation {
                    mode: IsolationMode::InProcess,
                    reason: "",
                },
            }
        }
        fn policy_media_type(&self) -> &'static str {
            "application/vnd.permguard.policy.fragile"
        }
        fn schema_media_type(&self) -> Option<&'static str> {
            None
        }
        fn validate_policy(&self, _bytes: &[u8]) -> Result<(), String> {
            Ok(())
        }
        fn declared_alias(&self, _source: &[u8]) -> Result<Option<String>, String> {
            Ok(None)
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

    /// A compile that comes apart is the load's refusal, and the refusal never carries the panic's
    /// words.
    #[test]
    fn a_guarded_compile_refuses_instead_of_panicking() {
        let refused = Guarded(Fragile)
            .compile(&[], &Artifacts::default())
            .err()
            .expect("refused");

        assert!(
            refused.contains("came apart compiling a partition"),
            "{refused}"
        );
        assert!(!refused.contains("secret"), "{refused}");
    }
}
