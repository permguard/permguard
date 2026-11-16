// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! Reading one partition out of a commit: the walk (`permguard-language-core`), over the runtime
//! this build carries under the name the partition declares.

use permguard_objects::manifest::Partition;

pub use permguard_language_core::partition::*;

/// Reads one partition's subtree, and checks it against what the manifest declared, with the
/// runtime the partition names.
///
/// A runtime this build does not carry is refused as incompatible before anything is read: the
/// partition was written for an engine this build is not.
pub fn collect(
    objects: &dyn Objects,
    root: &str,
    partition: &str,
    declared: &Partition,
) -> Result<Collected, Collecting> {
    let Some(language) = crate::lookup::language(&declared.runtime) else {
        return Err(Collecting::Incompatible(format!(
            "the partition `{partition}` names the runtime `{}`, which this build does not carry",
            declared.runtime
        )));
    };

    collect_with(language, objects, root, partition, declared)
}
