// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! Rego, through Microsoft's `regorus` interpreter.
//!
//! A Rego module is the unit: rules are not standalone, so one file is one
//! policy — the whole verbatim source. The alias rides the standard OPA
//! `# METADATA` annotation block, under `custom.alias`; no bespoke syntax.

mod evaluate;

use crate::role::{Authoring, ExtractedPolicy, Language};

/// This language's name, as a manifest's `runtime.language.name` and an `entities.schema` spell it.
pub const NAME: &str = "rego";

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
        None
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

#[cfg(test)]
mod tests {
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
}
