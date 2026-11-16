// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! Registering an engine in the process's catalogue (`11-refactoring/1-dependencies.md`, Target
//! dependency layers: registration is deterministic, and never replaces).
//!
//! One test, in a file of its own: the catalogue is the process's, read once and sealed, so
//! nothing else may read it first. A language a feature of this build already carries is refused
//! as a duplicate, and so is any engine once the catalogue was read. The engine an application
//! registers for a language no feature carries is proven where no feature carries one: the
//! reference embedding application, outside the workspace.

#![cfg(all(feature = "evaluate", feature = "cedar"))]
#![allow(clippy::expect_used)]

use permguard_languages::{Unregistered, register};

#[test]
fn test_an_engine_is_never_replaced_and_never_added_to_a_catalogue_already_read() {
    let cedar = permguard_language_cedar::engine();
    assert_eq!(cedar.name(), "cedar");

    // The build's feature carries Cedar: a second engine for it is refused, and said so.
    let refused = register(cedar).expect_err("the catalogue already holds Cedar");
    assert_eq!(refused, Unregistered::Duplicate("cedar".to_owned()));
    assert!(refused.to_string().contains("never replaced"), "{refused}");

    // The refusal changed nothing, and the order is the catalogue's own.
    let names: Vec<&str> = permguard_languages::languages()
        .iter()
        .map(|language| language.name())
        .collect();
    assert_eq!(
        names.iter().filter(|name| **name == "cedar").count(),
        1,
        "{names:?}"
    );
    let mut sorted = names.clone();
    sorted.sort_by_key(|name| {
        ["cedar", "dogwood", "rego"]
            .iter()
            .position(|held| held == name)
    });
    assert_eq!(names, sorted, "the catalogue keeps one fixed order");
    assert_eq!(
        permguard_languages::lookup::evaluators()
            .iter()
            .map(|(name, _)| *name)
            .collect::<Vec<_>>(),
        names,
        "both halves in the same order"
    );

    // Read, so sealed: nothing is registered any more, whatever it is.
    let late = register(cedar).expect_err("the catalogue was read");
    assert_eq!(late, Unregistered::Sealed("cedar".to_owned()));
}
