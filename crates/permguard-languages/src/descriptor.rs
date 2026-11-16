// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! What a language is, in one immutable object, and the digest that names it: the descriptor model
//! (`permguard-language-core`), and the descriptors of the languages this build carries.

use std::sync::LazyLock;

pub use permguard_language_core::descriptor::*;

/// Every carried language's descriptor and digest, computed once.
static DIGESTS: LazyLock<Vec<(&'static str, Descriptor, String)>> = LazyLock::new(|| {
    crate::lookup::languages()
        .iter()
        .map(|language| {
            let descriptor = Descriptor::of(*language);
            let digest = descriptor.digest();
            (language.name(), descriptor, digest)
        })
        .collect()
});

/// The descriptor of the carried language `name`.
pub fn descriptor(name: &str) -> Option<&'static Descriptor> {
    DIGESTS
        .iter()
        .find(|(held, _, _)| *held == name)
        .map(|(_, descriptor, _)| descriptor)
}

/// The descriptor digest of the carried language `name`: what a compiled-partition cache key
/// names the runtime by, so a program compiled by another engine build is never served.
pub fn descriptor_digest(name: &str) -> Option<&'static str> {
    DIGESTS
        .iter()
        .find(|(held, _, _)| *held == name)
        .map(|(_, _, digest)| digest.as_str())
}
