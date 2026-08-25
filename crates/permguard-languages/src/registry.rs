// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The dispatch: from a media type to the language that owns it.
//!
//! This is the layer that knows a catalogue of languages exists — which is
//! why it lives here and not in the object model. The model defines what an
//! object *is*; whether a blob's payload is legal Cedar is a question only
//! whoever holds the languages can answer, and both sides ask it here so
//! they cannot drift: the control plane at ingest, the CLI at build.

use permguard_objects::manifest::{Manifest, ProvidedRuntime};
use permguard_objects::semver::Version;

use crate::lookup::{language_for_media_type, languages};
use crate::role::Language;

/// The registered media types of the built-in languages. Each language owns
/// its own; the model knows only the family prefix and its own manifest.
pub const MEDIA_TYPE_POLICY_CEDAR: &str = "application/vnd.permguard.policy.cedar";
pub const MEDIA_TYPE_SCHEMA_CEDAR: &str = "application/vnd.permguard.schema.cedar";
pub const MEDIA_TYPE_POLICY_REGO: &str = "application/vnd.permguard.policy.rego";
pub const MEDIA_TYPE_MANIFEST: &str = permguard_objects::manifest::MEDIA_TYPE;

/// The engine identity of this build, for the manifest load gate.
pub const ENGINE_NAME: &str = "permguard";
pub const ENGINE_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Why a blob was refused: a stable code plus the sentence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlobRejected {
    pub code: &'static str,
    pub message: String,
}

impl std::fmt::Display for BlobRejected {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for BlobRejected {}

/// What this build provides to the load gate: its engine plus every
/// language it carries. Fixed at compile time, like the languages.
pub fn provided_runtimes() -> Vec<ProvidedRuntime> {
    let fallback = Version {
        major: 0,
        minor: 0,
        patch: 0,
    };
    let engine_version = Version::parse(ENGINE_VERSION).unwrap_or(fallback);
    languages()
        .iter()
        .map(|language| ProvidedRuntime {
            language_name: language.name().to_owned(),
            language_version: Version::parse(language.language_version()).unwrap_or(fallback),
            engine_name: ENGINE_NAME.to_owned(),
            engine_version,
        })
        .collect()
}

/// Validates one blob against its registered media type — the ingest rule,
/// run by the server on what arrives and by the client on what it builds.
/// An unregistered media type is rejected, fail-closed, never stored as
/// "unknown opaque bytes".
pub fn validate_blob(media_type: &str, data: &[u8]) -> Result<(), BlobRejected> {
    let rejected = |code: &'static str, message: String| BlobRejected { code, message };

    if media_type == MEDIA_TYPE_MANIFEST {
        // The manifest is the model's own object, and the model validates it.
        return Manifest::decode(data)
            .map(|_| ())
            .map_err(|e| rejected("manifest_rejected", e.to_string()));
    }
    let Some(language) = language_for_media_type(media_type) else {
        return Err(rejected(
            "media_type_unregistered",
            format!("`{media_type}` is not a registered media type"),
        ));
    };
    if language.schema_media_type() == Some(media_type) {
        language
            .validate_schema(data)
            .map_err(|e| rejected("blob_rejected", e))
    } else {
        language
            .validate_policy(data)
            .map_err(|e| rejected("blob_rejected", e))
    }
}

/// The alias a policy source declares, read by its own language — the
/// author's optional handle, which carries identity across renames and
/// never *is* the identity. The ingest path checks the annotation mirrors it.
pub fn declared_alias(media_type: &str, source: &[u8]) -> Option<String> {
    language_for_media_type(media_type)?.declared_alias(source)
}

/// The language a media type belongs to, for callers that need the language
/// itself rather than an answer about one blob.
pub fn language_of(media_type: &str) -> Option<&'static dyn Language> {
    language_for_media_type(media_type)
}

/// The evaluating half of a language named by the manifest, when this build
/// carries one.
///
/// The data plane's entry point into the catalogue: a manifest names a
/// language, and this is what turns that name into something that can decide.
/// A language this build does not carry — or carries without an engine — is
/// `None`, and the load is refused rather than answered best-effort.
pub fn evaluating(language_name: &str) -> Option<&'static dyn crate::evaluate::Evaluating> {
    crate::lookup::language(language_name)?.evaluating()
}
