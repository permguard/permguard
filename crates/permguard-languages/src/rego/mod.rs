// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! Rego, through Microsoft's `regorus` interpreter.
//!
//! A Rego module is the unit: rules are not standalone, so one file is one
//! policy — the whole verbatim source. The alias rides the standard OPA
//! `# METADATA` annotation block, under `custom.alias`; no bespoke syntax.

pub(crate) mod evaluate;

use crate::role::{Authoring, ExtractedPolicy, Language};

/// This language's name, as a manifest's `runtime.language.name` spells it.
pub const NAME: &str = "rego";

/// The registered media type of a Rego partition's schema.
///
/// The content is **JSON Schema**, not Rego: what a schema describes here is the document a
/// request hands the partition (`input.partition`), and JSON Schema is what describes JSON. The
/// media type says so in its suffix, so nothing has to guess from a file name.
pub const SCHEMA_MEDIA_TYPE: &str = "application/vnd.permguard.schema.rego+json";

/// The extension an authored Rego partition schema carries.
pub const SCHEMA_EXTENSION: &str = "regoschema";

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

    fn policy_media_type(&self) -> &'static str {
        "application/vnd.permguard.policy.rego"
    }

    fn schema_media_type(&self) -> Option<&'static str> {
        Some(SCHEMA_MEDIA_TYPE)
    }

    fn artifacts(&self) -> &'static [&'static dyn crate::artifact::ArtifactType] {
        const SCHEMA: &SchemaArtifact = &SchemaArtifact;

        &[SCHEMA]
    }

    fn validate_schema(&self, bytes: &[u8]) -> Result<(), String> {
        evaluate::compile_schema(bytes).map(|_| ())
    }

    fn validate_policy(&self, bytes: &[u8]) -> Result<(), String> {
        let text = std::str::from_utf8(bytes)
            .map_err(|_| "a Rego module must be valid UTF-8".to_owned())?;
        let mut engine = regorus::Engine::new();
        engine
            .add_policy("policy.rego".to_owned(), text.to_owned())
            .map(|_| ())
            .map_err(|error| format!("rego: {error}"))
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
            let Some(package) = package_of(source) else {
                continue;
            };
            if let Some(first) = claimed.get(&package) {
                return Err(crate::rego::evaluate::shared_package(&package, first, name));
            }
            claimed.insert(package, name);
        }

        Ok(())
    }

    fn declared_alias(&self, source: &[u8]) -> Option<String> {
        let text = std::str::from_utf8(source).ok()?;
        alias_of(text)
    }

    fn authoring(&self) -> Option<&dyn Authoring> {
        Some(self)
    }

    fn evaluating(&self) -> Option<&dyn crate::evaluate::Evaluating> {
        Some(self)
    }
}

/// The declared alias: the standard OPA `# METADATA` block, `custom.alias`.
///
/// The block is the comment lines immediately preceding (or heading) the
/// module; its content is YAML behind the `# ` prefix — parsed as such,
/// never scraped with guesses.
fn alias_of(text: &str) -> Option<String> {
    let mut yaml = String::new();
    let mut in_block = false;
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed == "# METADATA" {
            in_block = true;
            continue;
        }
        if in_block {
            if let Some(rest) = trimmed.strip_prefix("#") {
                yaml.push_str(rest.strip_prefix(' ').unwrap_or(rest));
                yaml.push('\n');
            } else {
                break;
            }
        }
    }
    if yaml.is_empty() {
        return None;
    }
    let value: serde_norway::Value = serde_norway::from_str(&yaml).ok()?;
    value
        .get("custom")?
        .get("alias")?
        .as_str()
        .map(ToOwned::to_owned)
}

impl Authoring for Rego {
    fn file_extensions(&self) -> &'static [&'static str] {
        &["rego"]
    }

    fn schema_file_extensions(&self) -> &'static [&'static str] {
        &[SCHEMA_EXTENSION]
    }

    fn extract(&self, source: &[u8]) -> Result<Vec<ExtractedPolicy>, String> {
        self.validate_policy(source)?;
        let text = std::str::from_utf8(source)
            .map_err(|_| "a Rego module must be valid UTF-8".to_owned())?;
        Ok(vec![ExtractedPolicy {
            bytes: source.to_vec(),
            alias: alias_of(text),
        }])
    }
}

/// The registered type of a Rego partition's schema.
///
/// Described through the registry like every other artifact, so the legacy manifest flag
/// `schema: true` names a type rather than a special case in the walk.
pub const SCHEMA_ARTIFACT: &str = "permguard.rego.schema.v1";

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

/// The package a module declares, read from its own source.
///
/// Read here rather than by adding it to an engine, because this runs at authoring where the
/// question is "may these files live together" and not "does this whole set compile". A line-by-line
/// read is enough for that and cannot fail on a module whose *body* has a problem the set check is
/// not about.
fn package_of(source: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(source).ok()?;
    for line in text.lines() {
        let line = line.trim();
        if line.starts_with('#') {
            continue;
        }
        let Some(rest) = line.strip_prefix("package") else {
            continue;
        };
        // `package` must be followed by whitespace: `packages` is not a declaration.
        if !rest.starts_with(char::is_whitespace) {
            continue;
        }
        let named = rest.trim();
        if named.is_empty() {
            continue;
        }

        return Some(named.to_owned());
    }

    None
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
