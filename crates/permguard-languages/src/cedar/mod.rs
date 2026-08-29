// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! Cedar, through the official `cedar-policy` crate.
//!
//! A Cedar file may hold many policies; each is versioned on its own. The
//! splitter walks the source once — string- and comment-aware — and cuts at
//! the `;` that closes each policy at nesting depth zero, so every policy's
//! bytes are the **verbatim authored slice**, annotations included, never a
//! re-rendering. Each slice is then parsed by Cedar itself: the splitter
//! decides *where* a policy ends, the official parser decides *whether* it
//! is one.

mod evaluate;

use std::str::FromStr as _;

use crate::role::{Authoring, ExtractedPolicy, Language};

/// This language's name, as a manifest's `runtime.language.name` spells it.
pub const NAME: &str = "cedar";
/// The registered media type of a Cedar policy.
pub const POLICY_MEDIA_TYPE: &str = "application/vnd.permguard.policy.cedar";
/// The registered media type of a Cedar schema.
pub const SCHEMA_MEDIA_TYPE: &str = "application/vnd.permguard.schema.cedar";

/// The Cedar plugin.
pub struct Cedar;

impl Language for Cedar {
    fn name(&self) -> &'static str {
        NAME
    }

    fn language_version(&self) -> &'static str {
        // The language version the linked cedar-policy crate implements.
        "4.12.0"
    }

    fn policy_media_type(&self) -> &'static str {
        POLICY_MEDIA_TYPE
    }

    fn schema_media_type(&self) -> Option<&'static str> {
        Some(SCHEMA_MEDIA_TYPE)
    }

    fn artifacts(&self) -> &'static [&'static dyn crate::artifact::ArtifactType] {
        const SCHEMA: &SchemaArtifact = &SchemaArtifact;

        &[SCHEMA]
    }

    fn validate_policy(&self, bytes: &[u8]) -> Result<(), String> {
        let text = std::str::from_utf8(bytes)
            .map_err(|_| "a Cedar policy must be valid UTF-8".to_owned())?;
        cedar_policy::Policy::from_str(text)
            .map(|_| ())
            .map_err(|error| format!("cedar: {error}"))
    }

    fn validate_schema(&self, bytes: &[u8]) -> Result<(), String> {
        let text = std::str::from_utf8(bytes)
            .map_err(|_| "a Cedar schema must be valid UTF-8".to_owned())?;
        cedar_policy::Schema::from_cedarschema_str(text)
            .map(|_| ())
            .map_err(|error| format!("cedar schema: {error}"))
    }
    /// Cedar's marker is the `@alias("…")` annotation of the first policy.
    fn declared_alias(&self, source: &[u8]) -> Option<String> {
        let text = std::str::from_utf8(source).ok()?;
        alias_of(text)
    }

    /// The set-level check the data plane's load gate runs, run early: parse
    /// every policy, and — when the partition has a schema — validate the
    /// whole set against it in **strict** mode. One implementation for
    /// authoring, commit acceptance and load, so the three can never disagree
    /// about what satisfies a schema.
    fn validate_set(
        &self,
        policies: &[(&str, &[u8])],
        schema: Option<&[u8]>,
    ) -> Result<(), String> {
        let mut set = cedar_policy::PolicySet::new();
        for (name, bytes) in policies {
            let text = std::str::from_utf8(bytes)
                .map_err(|_| format!("cedar: policy {name} is not valid UTF-8"))?;
            let policy = cedar_policy::Policy::from_str(text)
                .map_err(|error| format!("cedar: policy {name} does not parse: {error}"))?;
            let id = cedar_policy::PolicyId::from_str(name)
                .map_err(|error| format!("cedar: policy id {name}: {error}"))?;
            set.add(policy.new_id(id))
                .map_err(|error| format!("cedar: policy {name}: {error}"))?;
        }
        if let Some(bytes) = schema {
            let schema = parse_schema(bytes)?;
            check_against_schema(&set, &schema)?;
        }

        Ok(())
    }

    fn authoring(&self) -> Option<&dyn Authoring> {
        Some(self)
    }

    fn evaluating(&self) -> Option<&dyn crate::evaluate::Evaluating> {
        Some(self)
    }
}

/// Parses a Cedar schema from its authored text.
pub(super) fn parse_schema(bytes: &[u8]) -> Result<cedar_policy::Schema, String> {
    let text = std::str::from_utf8(bytes)
        .map_err(|_| "cedar: the schema is not valid UTF-8".to_owned())?;
    let (schema, _warnings) = cedar_policy::Schema::from_cedarschema_str(text)
        .map_err(|error| format!("cedar: the schema does not parse: {error}"))?;

    Ok(schema)
}

/// Validates a policy set against its schema, strict mode.
///
/// The one definition of "satisfies the schema" — authoring, commit
/// acceptance and the data plane's load all call this, which is what makes
/// the promise "what validates is what serves" a fact rather than a hope.
pub(super) fn check_against_schema(
    set: &cedar_policy::PolicySet,
    schema: &cedar_policy::Schema,
) -> Result<(), String> {
    use cedar_policy::{ValidationMode, Validator};

    let result = Validator::new(schema.clone()).validate(set, ValidationMode::Strict);
    if !result.validation_passed() {
        let refused: Vec<String> = result
            .validation_errors()
            .map(|error| error.to_string())
            .collect();

        return Err(format!(
            "cedar: the policies do not satisfy the partition's schema: {}",
            refused.join("; ")
        ));
    }

    Ok(())
}

/// The declared alias: Cedar's `@alias("…")` annotation, first occurrence.
fn alias_of(policy: &str) -> Option<String> {
    let start = policy.find("@alias(\"")? + "@alias(\"".len();
    let end = policy[start..].find("\")")? + start;
    Some(policy[start..end].to_string())
}

/// Cuts a Cedar source at every policy-terminating `;`: nesting depth zero,
/// outside strings and line comments. Returns the trimmed verbatim slices,
/// comment-only remainders dropped.
fn split_policies(text: &str) -> Vec<&str> {
    let bytes = text.as_bytes();
    let mut slices = Vec::new();
    let mut start = 0usize;
    let mut depth: i64 = 0;
    let mut in_string = false;
    let mut escaped = false;
    let mut in_comment = false;
    let mut at = 0usize;

    while at < bytes.len() {
        let c = bytes[at];
        if in_comment {
            if c == b'\n' {
                in_comment = false;
            }
        } else if in_string {
            if escaped {
                escaped = false;
            } else if c == b'\\' {
                escaped = true;
            } else if c == b'"' {
                in_string = false;
            }
        } else {
            match c {
                b'"' => in_string = true,
                b'/' if at + 1 < bytes.len() && bytes[at + 1] == b'/' => in_comment = true,
                b'{' | b'(' | b'[' => depth += 1,
                b'}' | b')' | b']' => depth -= 1,
                b';' if depth == 0 => {
                    let slice = text[start..=at].trim();
                    if !is_blank(slice) {
                        slices.push(slice);
                    }
                    start = at + 1;
                }
                _ => {}
            }
        }
        at += 1;
    }
    // Whatever trails without a `;` is left for the parser to refuse — a
    // truncated policy must be an error, not silently dropped.
    let tail = text[start..].trim();
    if !is_blank(tail) {
        slices.push(tail);
    }
    slices
}

/// Whether a slice holds nothing but whitespace and line comments.
fn is_blank(slice: &str) -> bool {
    slice
        .lines()
        .all(|line| line.trim().is_empty() || line.trim().starts_with("//"))
}

impl Authoring for Cedar {
    fn schema_file_extensions(&self) -> &'static [&'static str] {
        &[SCHEMA_EXTENSION]
    }

    fn file_extensions(&self) -> &'static [&'static str] {
        &["cedar"]
    }

    fn extract(&self, source: &[u8]) -> Result<Vec<ExtractedPolicy>, String> {
        let text = std::str::from_utf8(source)
            .map_err(|_| "a Cedar source must be valid UTF-8".to_owned())?;
        let mut policies = Vec::new();
        for slice in split_policies(text) {
            self.validate_policy(slice.as_bytes())?;
            policies.push(ExtractedPolicy {
                bytes: slice.as_bytes().to_vec(),
                alias: alias_of(slice),
            });
        }
        Ok(policies)
    }
}

/// The registered type of a Cedar partition's schema.
///
/// Cedar's one schema, described the same way every other artifact is. It exists so nothing
/// downstream has to keep a second, older idea of what a partition holds beside the registry: the
/// legacy manifest flag `schema: true` names *this* type, and the walk that reads a Cedar
/// partition is the walk that reads a Dogwood one.
pub const SCHEMA_ARTIFACT: &str = "permguard.cedar.schema.v1";
/// The file extension a Cedar schema is authored in.
pub const SCHEMA_EXTENSION: &str = "cedarschema";

/// The Cedar schema artifact.
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
        crate::role::Language::validate_schema(&Cedar, bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TWO: &str = r#"// billing policies
@alias("billing-ro")
permit (
    principal in Group::"finance",
    action == Action::"read",
    resource
);

permit (principal, action == Action::"list", resource);
"#;

    #[test]
    fn splits_two_policies_verbatim() {
        let policies = Cedar.extract(TWO.as_bytes()).unwrap();
        assert_eq!(policies.len(), 2);
        // Verbatim means the leading comment travels with its policy.
        assert!(policies[0].bytes.starts_with(b"// billing policies"));
        assert_eq!(policies[0].alias.as_deref(), Some("billing-ro"));
        assert_eq!(policies[1].alias, None);
        // Verbatim: the slice ends exactly at its `;`.
        assert!(policies[0].bytes.ends_with(b";"));
    }

    #[test]
    fn semicolons_inside_strings_do_not_split() {
        let source = r#"permit (principal, action, resource) when { resource.tag == "a;b" };"#;
        let policies = Cedar.extract(source.as_bytes()).unwrap();
        assert_eq!(policies.len(), 1);
    }

    #[test]
    fn broken_cedar_is_refused() {
        assert!(Cedar.extract(b"permit (principal").is_err());
        assert!(Cedar.validate_policy(b"not cedar at all;").is_err());
    }

    #[test]
    fn schema_validation() {
        let schema = r#"
entity User;
entity Document;
action read appliesTo { principal: [User], resource: [Document] };
"#;
        assert!(Cedar.validate_schema(schema.as_bytes()).is_ok());
        assert!(Cedar.validate_schema(b"entity ;;;").is_err());
    }
}
