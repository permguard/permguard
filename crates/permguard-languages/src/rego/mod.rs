// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! Rego, through Microsoft's `regorus` interpreter.
//!
//! A Rego module is the unit: rules are not standalone, so one file is one
//! policy — the whole verbatim source. The alias rides the standard OPA
//! `# METADATA` annotation block, under `custom.alias`; no bespoke syntax.

pub(crate) mod evaluate;
pub(crate) mod parsed;

use crate::role::{Authoring, ExtractedPolicy, Language};

/// This language's name, as a manifest's `runtime.language.name` spells it.
pub const NAME: &str = "rego";

/// The registered media type of a Rego partition's schema.
///
/// The content is **JSON Schema**, not Rego: what a schema describes here is the document a
/// request hands the partition (`input.partition`), and JSON Schema is what describes JSON. The
/// media type says so in its suffix, so nothing has to guess from a file name.
pub const SCHEMA_MEDIA_TYPE: &str = permguard_core::domains::media::SCHEMA_REGO_JSON;

/// The extension an authored Rego partition schema carries.
pub const SCHEMA_EXTENSION: &str = "regoschema";

/// The registered type of the whole-input schema, `permguard.rego.schema.v2`: JSON Schema over all
/// of `input` — `subject`, `resource`, `action`, `context` and `partition` — so a misspelled common
/// field is a typed refusal rather than an `undefined` a rule reads as "no" (REGO-06, IFACE-07).
pub const INPUT_SCHEMA_ARTIFACT: &str = permguard_core::domains::artifact::REGO_SCHEMA_V2;
/// The media type of the whole-input schema.
pub const INPUT_SCHEMA_MEDIA_TYPE: &str = permguard_core::domains::media::SCHEMA_REGO_INPUT_JSON;
/// The extension an authored whole-input schema carries.
pub const INPUT_SCHEMA_EXTENSION: &str = "regoinput";

/// The Rego plugin.
pub struct Rego;

impl Language for Rego {
    fn name(&self) -> &'static str {
        NAME
    }

    fn language_version(&self) -> &'static str {
        // Rego v1 semantics, as regorus implements them.
        "1.0.0"
    }

    fn engine(&self) -> crate::descriptor::Engine {
        use crate::descriptor::{Capabilities, Engine, Isolation, IsolationMode, locked};

        Engine {
            locked: locked::REGO,
            capabilities: Capabilities {
                features: crate::registry::engine_features::REGO,
                extensions: &[],
                // `time` gives `time.now_ns`; `std` gives `rand.intn` and `uuid` gives
                // `uuid.rfc4122`. Neither `http` nor `opa-runtime` reaches the network or the
                // environment in this build.
                // The allow-list refuses every built-in that reads the clock or draws randomness at
                // load, whatever the build compiled in (REGO-01).
                clock: false,
                randomness: false,
                io: false,
            },
            limits: &["rego_nesting", "rego_parse_work", "rego_partition_deadline"],
            isolation: Isolation {
                mode: IsolationMode::InProcess,
                reason: "one decreasing deadline bounds each partition's work; memory is not \
                         bounded in-process (LANG-04), so from production upward every partition \
                         compiles and evaluates in the supervised worker, or is refused",
            },
        }
    }

    fn policy_media_type(&self) -> &'static str {
        permguard_core::domains::media::POLICY_REGO
    }

    fn schema_media_type(&self) -> Option<&'static str> {
        Some(SCHEMA_MEDIA_TYPE)
    }

    fn artifacts(&self) -> &'static [&'static dyn crate::artifact::ArtifactType] {
        const SCHEMA: &SchemaArtifact = &SchemaArtifact;
        const INPUT: &InputSchemaArtifact = &InputSchemaArtifact;

        &[SCHEMA, INPUT]
    }

    /// Regorus has no hard memory bound in-process, and a comprehension or `walk` over hostile
    /// data can spend without limit: from `production` upward a Rego partition runs in a
    /// supervised worker, under the OS limits, or not at all (REGO-03, LANG-04).
    fn isolation_required(&self, profile: permguard_core::assurance::AssuranceProfile) -> bool {
        profile.at_least(permguard_core::assurance::AssuranceProfile::Production)
    }

    /// From `production` the partition carries a schema, v1 or v2; under `regulated` the
    /// whole-input v2, because v1 types only `input.partition` (REGO-06).
    fn required_schemas(
        &self,
        profile: permguard_core::assurance::AssuranceProfile,
    ) -> &'static [&'static str] {
        use permguard_core::assurance::AssuranceProfile;

        if profile.at_least(AssuranceProfile::Regulated) {
            &[INPUT_SCHEMA_ARTIFACT]
        } else if profile.at_least(AssuranceProfile::Production) {
            &[SCHEMA_ARTIFACT, INPUT_SCHEMA_ARTIFACT]
        } else {
            &[]
        }
    }

    fn validate_schema(&self, bytes: &[u8]) -> Result<(), String> {
        evaluate::compile_schema(bytes).map(|_| ())
    }

    /// The module parses, calls only allowed built-ins and declares a well-formed alias, if any:
    /// what authoring and the Control Plane's acceptance of a push check, read from the parsed
    /// tree as the load gate reads it.
    fn validate_policy(&self, bytes: &[u8]) -> Result<(), String> {
        let text = std::str::from_utf8(bytes)
            .map_err(|_| "a Rego module must be valid UTF-8".to_owned())?;
        let module = parsed::parse(text)?;
        parsed::check_builtins(&module)?;
        parsed::alias(text, &module).map(|_| ())
    }
    /// Rego's marker is `# METADATA` with `custom.alias`, above the package.
    /// Refuses a partition whose policies share a package.
    ///
    /// Run at authoring and at commit acceptance, where the error belongs to whoever wrote it —
    /// the compile refuses the same shape, so a ledger that reached a plane is refused there too,
    /// but by then the error belongs to whoever met it. See `evaluate::shared_package` for why it
    /// is a refusal rather than something to work around.
    fn validate_set(
        &self,
        policies: &[(&str, &[u8])],
        schema: Option<&[u8]>,
    ) -> Result<(), String> {
        let _ = schema;
        let mut claimed: std::collections::BTreeMap<String, &str> =
            std::collections::BTreeMap::new();
        for (name, source) in policies {
            // The package the parser reports, the value the compile and the load gate use too
            // (REGO-07): never a second, lexical reading of it.
            let text = std::str::from_utf8(source)
                .map_err(|_| format!("rego: policy {name} is not valid UTF-8"))?;
            let package = parsed::parse(text)
                .map_err(|error| format!("rego: policy {name}: {error}"))?
                .package;
            if let Some(first) = claimed.get(&package) {
                return Err(crate::rego::evaluate::shared_package(&package, first, name));
            }
            claimed.insert(package, name);
        }

        Ok(())
    }

    /// `custom.alias` of the `# METADATA` block heading the package the parser located.
    fn declared_alias(&self, source: &[u8]) -> Result<Option<String>, String> {
        let text = std::str::from_utf8(source)
            .map_err(|_| "a Rego module must be valid UTF-8".to_owned())?;
        parsed::alias(text, &parsed::parse(text)?)
    }

    fn authoring(&self) -> Option<&dyn Authoring> {
        Some(self)
    }

    fn evaluating(&self) -> Option<&dyn crate::evaluate::Evaluating> {
        Some(self)
    }
}

impl Authoring for Rego {
    fn file_extensions(&self) -> &'static [&'static str] {
        &["rego"]
    }

    fn schema_file_extensions(&self) -> &'static [&'static str] {
        &[SCHEMA_EXTENSION]
    }

    fn extract(&self, source: &[u8]) -> Result<Vec<ExtractedPolicy>, String> {
        let text = std::str::from_utf8(source)
            .map_err(|_| "a Rego module must be valid UTF-8".to_owned())?;
        let module = parsed::parse(text)?;
        parsed::check_builtins(&module)?;
        Ok(vec![ExtractedPolicy {
            bytes: source.to_vec(),
            alias: parsed::alias(text, &module)?,
        }])
    }
}

/// The registered type of a Rego partition's schema.
///
/// Described through the registry like every other artifact, so the legacy manifest flag
/// `schema: true` names a type rather than a special case in the walk.
pub const SCHEMA_ARTIFACT: &str = permguard_core::domains::artifact::REGO_SCHEMA_V1;

/// The Rego schema artifact.
pub struct SchemaArtifact;

impl crate::artifact::ArtifactType for SchemaArtifact {
    fn name(&self) -> &'static str {
        SCHEMA_ARTIFACT
    }

    fn media_type(&self) -> &'static str {
        SCHEMA_MEDIA_TYPE
    }

    fn runtime(&self) -> &'static str {
        NAME
    }

    fn role(&self) -> crate::artifact::ArtifactRole {
        crate::artifact::ArtifactRole::Schema
    }

    fn semantic_role(&self) -> &'static str {
        "schema"
    }

    fn extensions(&self) -> &'static [&'static str] {
        &[SCHEMA_EXTENSION]
    }

    fn cardinality(&self) -> crate::artifact::Cardinality {
        crate::artifact::Cardinality::ZeroOrOne
    }

    fn validate(&self, bytes: &[u8]) -> Result<(), String> {
        crate::role::Language::validate_schema(&Rego, bytes)
    }
}

/// The registered type of a Rego partition's whole-input schema.
pub struct InputSchemaArtifact;

impl crate::artifact::ArtifactType for InputSchemaArtifact {
    fn name(&self) -> &'static str {
        INPUT_SCHEMA_ARTIFACT
    }

    fn media_type(&self) -> &'static str {
        INPUT_SCHEMA_MEDIA_TYPE
    }

    fn runtime(&self) -> &'static str {
        NAME
    }

    fn role(&self) -> crate::artifact::ArtifactRole {
        crate::artifact::ArtifactRole::Schema
    }

    fn semantic_role(&self) -> &'static str {
        "input-schema"
    }

    fn extensions(&self) -> &'static [&'static str] {
        &[INPUT_SCHEMA_EXTENSION]
    }

    fn cardinality(&self) -> crate::artifact::Cardinality {
        crate::artifact::Cardinality::ZeroOrOne
    }

    fn validate(&self, bytes: &[u8]) -> Result<(), String> {
        evaluate::compile_schema(bytes).map(|_| ())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;

    const MODULE: &str = r#"# METADATA
# custom:
#   alias: gateway-routes
package gateway.routes

import rego.v1

default allow := false

allow if {
    input.subject.type == "user"
    input.action.name == "read"
}
"#;

    #[test]
    fn a_module_is_one_policy_with_its_alias() {
        let policies = Rego.extract(MODULE.as_bytes()).unwrap();
        assert_eq!(policies.len(), 1);
        assert_eq!(policies[0].alias.as_deref(), Some("gateway-routes"));
        assert_eq!(policies[0].bytes, MODULE.as_bytes());
    }

    #[test]
    fn no_metadata_means_no_alias() {
        let source = "package a\nimport rego.v1\ndefault allow := false\n";
        let policies = Rego.extract(source.as_bytes()).unwrap();
        assert_eq!(policies[0].alias, None);
    }

    #[test]
    fn broken_rego_is_refused() {
        assert!(Rego.validate_policy(b"package ???").is_err());
    }

    #[test]
    fn a_partition_schema_is_json_schema_and_is_checked_as_such() {
        assert!(
            Rego.validate_schema(br#"{"type": "object", "required": ["frozen_services"]}"#)
                .is_ok()
        );
        assert!(Rego.validate_schema(b"not json at all").is_err());
        // A schema whose own keywords are wrong is refused at load, not at the first request.
        assert!(Rego.validate_schema(br#"{"type": 7}"#).is_err());
    }

    #[test]
    fn a_schema_that_reaches_for_the_network_does_not_compile() {
        // No retriever is configured, so a remote `$ref` cannot resolve. A policy load that made
        // an outbound request would be one an operator cannot reason about.
        let refused = Rego
            .validate_schema(br#"{"$ref": "https://example.test/schema.json"}"#)
            .expect_err("a remote reference cannot resolve here");

        assert!(refused.contains("rego:"), "{refused}");
    }
}
