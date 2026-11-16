// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! An engine, as a value: the two halves of one language, handed over together.
//!
//! A language package hands out its language and its evaluating half behind one panic boundary.
//! An application that embeds the Data Plane and links a language package itself registers both at
//! once with this, so the catalogue never holds a language that validates under one engine and
//! evaluates under another.

use permguard_language_core::role::Language;

use crate::evaluate::Evaluating;

/// One language's validating and evaluating halves.
#[derive(Clone, Copy)]
pub struct Engine {
    language: &'static dyn Language,
    evaluating: &'static dyn Evaluating,
}

impl Engine {
    /// The engine whose halves are `language` and `evaluating`: the same language, both behind
    /// its package's panic boundary.
    pub fn new(language: &'static dyn Language, evaluating: &'static dyn Evaluating) -> Self {
        Self {
            language,
            evaluating,
        }
    }

    /// The canonical name of the language, as a manifest's runtime names it.
    pub fn name(&self) -> &'static str {
        self.language.name()
    }

    /// The validating half.
    pub fn language(&self) -> &'static dyn Language {
        self.language
    }

    /// The evaluating half.
    pub fn evaluating(&self) -> &'static dyn Evaluating {
        self.evaluating
    }
}

impl std::fmt::Debug for Engine {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Engine")
            .field("name", &self.name())
            .field("language_version", &self.language.language_version())
            .finish()
    }
}
