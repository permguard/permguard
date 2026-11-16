// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! What the catalogue's rules say of one language, without the catalogue: the assurance floors a
//! language's own artifacts are held to. The catalogue that finds a language by its name, and every
//! rule over all of them, are `permguard-languages`'.

use crate::artifact::Artifacts;
use crate::role::Language;

/// The artifact a floor that came apart refuses: every one, so every partition is refused.
pub const EVERY_ARTIFACT: &str = "every artifact, the floor having come apart";

/// Refuses a partition of `language` that carries none of the schemas its language requires at
/// `profile`.
pub fn check_schema_floor_of(
    language: &dyn Language,
    profile: permguard_core::assurance::AssuranceProfile,
    artifacts: &Artifacts,
) -> Result<(), String> {
    let required = language.required_schemas(profile);
    if required.is_empty() || required.iter().any(|name| artifacts.bytes(name).is_some()) {
        return Ok(());
    }

    Err(format!(
        "a `{}` partition carries none of {}, which the `{}` assurance profile requires",
        language.name(),
        required
            .iter()
            .map(|name| format!("`{name}`"))
            .collect::<Vec<_>>()
            .join(", "),
        profile.as_str()
    ))
}

/// Refuses a partition of `language` that carries an artifact its language may not carry at
/// `profile`.
///
/// The load gate's other half of the assurance floor (DOGWOOD-01): checked against what the
/// partition actually carries, so a manifest cannot declare its way around it.
pub fn check_artifact_floor_of(
    language: &dyn Language,
    profile: permguard_core::assurance::AssuranceProfile,
    artifacts: &Artifacts,
) -> Result<(), String> {
    let refused = language.refused_artifacts(profile);
    let carried = refused
        .iter()
        .find(|name| **name == EVERY_ARTIFACT || !artifacts.all(name).is_empty());
    let Some(carried) = carried else {
        return Ok(());
    };

    Err(format!(
        "a `{}` partition carries `{carried}`, which the `{}` assurance profile refuses: this \
         runtime cannot bound it in-process and runs no worker for it",
        language.name(),
        profile.as_str()
    ))
}
