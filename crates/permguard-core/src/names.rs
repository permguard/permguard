// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! Canonical names shared by stream stores, configuration and cursors.

/// Whether `name` is one exact, portable filesystem segment.
///
/// Leading or trailing whitespace is refused rather than normalized: normalizing turns two wire
/// identities into one directory. The stricter ASCII alphabet keeps decision producer names
/// portable across every filesystem Permguard supports.
pub fn is_portable_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 128
        && name == name.trim()
        && !name.starts_with('.')
        && name.chars().all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.')
        })
}
