// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! What a request may hand a partition: the input registry (`permguard-language-core`), and the
//! input types of the languages this build carries.
//!
//! The registry names every input type Permguard defines, each written for one runtime. A build
//! offers a manifest, and holds its own startup check to, only those whose runtime it carries: an
//! input nothing here can read is not one this build implements.

use std::sync::LazyLock;

pub use permguard_language_core::input::*;

/// Every input type this build implements, in the registry's order: those written for a language
/// it carries.
pub fn input_types() -> &'static [&'static dyn InputType] {
    static CARRIED: LazyLock<Vec<&'static dyn InputType>> = LazyLock::new(|| {
        permguard_language_core::input::input_types()
            .iter()
            .copied()
            .filter(|held| crate::lookup::language(held.runtime()).is_some())
            .collect()
    });
    CARRIED.as_slice()
}

/// The input type of that name, when this build implements one.
pub fn input_type(name: &str) -> Option<&'static dyn InputType> {
    input_types()
        .iter()
        .copied()
        .find(|held| held.name() == name)
}

/// What this build offers the manifest's input gate.
pub fn provided_input_types() -> Vec<permguard_objects::manifest::ProvidedInputType> {
    input_types()
        .iter()
        .map(|held| permguard_objects::manifest::ProvidedInputType {
            name: held.name().to_owned(),
            language: held.runtime().to_owned(),
        })
        .collect()
}

/// The names of every input type this build implements, for a message that has to list them.
pub fn registered() -> String {
    input_types()
        .iter()
        .map(|held| held.name())
        .collect::<Vec<&str>>()
        .join(", ")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every input this build offers is written for a language it carries, and every input of a
    /// carried language is offered: the registry's, filtered by the catalogue and by nothing else.
    #[test]
    fn the_inputs_offered_are_those_of_the_languages_carried() {
        for held in input_types() {
            assert!(
                crate::lookup::language(held.runtime()).is_some(),
                "`{}` is written for `{}`, which this build does not carry",
                held.name(),
                held.runtime()
            );
        }
        for held in permguard_language_core::input::input_types() {
            assert_eq!(
                input_type(held.name()).is_some(),
                crate::lookup::language(held.runtime()).is_some(),
                "`{}`",
                held.name()
            );
        }
    }
}
