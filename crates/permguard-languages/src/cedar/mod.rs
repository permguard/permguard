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
pub const POLICY_MEDIA_TYPE: &str = permguard_core::domains::media::POLICY_CEDAR;
/// The registered media type of a Cedar schema.
pub const SCHEMA_MEDIA_TYPE: &str = permguard_core::domains::media::SCHEMA_CEDAR;

/// The Cedar plugin.
pub struct Cedar;

impl Language for Cedar {
    fn name(&self) -> &'static str {
        NAME
    }

    fn language_version(&self) -> &'static str {
        // Cedar's language is versioned by its engine's releases: the version is the locked
        // `cedar-policy`'s, read from `Cargo.lock` at build time and never written by hand.
        crate::descriptor::locked::CEDAR.version
    }

    fn engine(&self) -> crate::descriptor::Engine {
        use crate::descriptor::{Capabilities, Engine, Isolation, IsolationMode, locked};

        Engine {
            locked: locked::CEDAR,
            capabilities: Capabilities {
                features: crate::registry::engine_features::CEDAR,
                // The extension types those features add; none reads the clock or draws a value.
                extensions: &["datetime", "decimal", "ipaddr"],
                clock: false,
                randomness: false,
                io: false,
            },
            limits: &[],
            isolation: Isolation {
                mode: IsolationMode::InProcess,
                reason: "Cedar evaluation terminates by construction and holds no state between \
                         requests",
            },
        }
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
        parse_policy(text).map(|_| ())
    }

    fn validate_schema(&self, bytes: &[u8]) -> Result<(), String> {
        let text = std::str::from_utf8(bytes)
            .map_err(|_| "a Cedar schema must be valid UTF-8".to_owned())?;
        check_nesting(text, Grammar::Schema).map_err(|error| format!("cedar schema: {error}"))?;
        crate::headroom::ample(|| {
            cedar_policy::Schema::from_cedarschema_str(text)
                .map(|_| ())
                .map_err(|error| format!("cedar schema: {error}"))
        })
    }
    /// Cedar's marker is the `@alias("…")` annotation of the first policy, read from the parsed
    /// policy: text inside a comment or a string is never an alias.
    fn declared_alias(&self, source: &[u8]) -> Result<Option<String>, String> {
        let text = std::str::from_utf8(source)
            .map_err(|_| "a Cedar policy must be valid UTF-8".to_owned())?;
        match split_policies(text).first() {
            Some(first) => alias_of(first),
            None => Ok(None),
        }
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
            let policy = parse_policy(text)
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

    /// From `production` upward a Cedar partition carries a schema (CEDAR-05): untyped Cedar
    /// evaluates whatever the request says an entity is, and a policy reads differently than it
    /// runs. Schema-less Cedar remains a development compatibility mode.
    fn schema_required(&self, profile: permguard_core::assurance::AssuranceProfile) -> bool {
        profile.at_least(permguard_core::assurance::AssuranceProfile::Production)
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
    check_nesting(text, Grammar::Schema)
        .map_err(|error| format!("cedar: the schema does not parse: {error}"))?;
    let (schema, _warnings) = crate::headroom::ample(|| {
        cedar_policy::Schema::from_cedarschema_str(text)
            .map_err(|error| format!("cedar: the schema does not parse: {error}"))
    })?;

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

    // The strict validator recurses on each policy's tree: on a stack segment sized for the bound,
    // whichever thread — a Control Plane accepting a push included — asked.
    let result = crate::headroom::ample(|| {
        Validator::new(schema.clone()).validate(set, ValidationMode::Strict)
    });
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

/// The declared alias of one policy: its `@alias("…")` annotation, as the official parser decoded
/// it (CEDAR-03).
///
/// Never a search over the source: an `@alias(` inside a comment or a string literal is text, and
/// text must not become audit identity. Cedar's parser decodes the escapes and refuses a policy
/// that repeats an annotation, so the value here is the one canonical value; it is then held to
/// the common identity grammar.
fn alias_of(policy: &str) -> Result<Option<String>, String> {
    let parsed = parse_policy(policy)?;
    let Some(alias) = parsed.annotation(ALIAS_ANNOTATION) else {
        return Ok(None);
    };
    crate::role::identity_alias(alias).map_err(|error| format!("cedar: {error}"))?;

    Ok(Some(alias.to_owned()))
}

/// How deep a policy or a schema may nest: brackets (parentheses, square brackets, braces), and
/// the constructs Cedar nests without them — an `if` in a policy, a `Set<…>` in a schema.
///
/// Cedar's parser recurses on nesting, so the depth of the text is the depth of the stack it
/// needs: about 40 levels overflow a 2 MiB stack in a debug build, about 200 an 8 MiB one. The
/// bound is checked before the parser ever runs, wherever a Cedar text is parsed — authoring, the
/// Control Plane's acceptance of a push, the Data Plane's load — so one pushed policy cannot take
/// down the process that reads it. Real policies nest a handful of levels.
pub const MAX_NESTING: usize = 32;

/// Which grammar a text is in: what nests differs between the two.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Grammar {
    /// A policy: `if … then … else` nests in its branches without a bracket, and an `else if`
    /// chain is a recursion per link for the parser and the evaluator alike. Every `if` counts as a
    /// level, conservatively: a real policy holds a few. A member chain, `a.b.c`, nests one level
    /// per link too, and a `has` path costs time that grows with its square.
    Policy,
    /// A schema: `Set<…>` nests on angle brackets, which a schema uses for nothing else.
    Schema,
}

/// Refuses a text that nests deeper than [`MAX_NESTING`], scanning as the splitter does: outside
/// strings and line comments, where a bracket or a keyword is syntax.
pub(crate) fn check_nesting(text: &str, grammar: Grammar) -> Result<(), String> {
    let bytes = text.as_bytes();
    let (mut depth, mut deepest, mut ifs, mut chain) = (0usize, 0usize, 0usize, 0usize);
    let word = |c: Option<&u8>| c.is_some_and(|c| c.is_ascii_alphanumeric() || *c == b'_');
    let (mut in_string, mut escaped, mut in_comment) = (false, false, false);
    for (at, &c) in bytes.iter().enumerate() {
        if in_comment {
            in_comment = c != b'\n';
        } else if in_string {
            if escaped {
                escaped = false;
            } else if c == b'\\' {
                escaped = true;
            } else if c == b'"' {
                in_string = false;
            }
        } else {
            // A member chain, `a.b.c` or a `has a.b.c` path, folds into one node per link: a run
            // of consecutive `.` is a level per link. Cedar has no decimal literal outside a
            // string, so a `.` there is always a member access; any other token ends the run.
            if grammar == Grammar::Policy {
                if c == b'.' {
                    chain += 1;
                } else if !(word(Some(&c)) || c.is_ascii_whitespace()) {
                    chain = 0;
                }
            }
            match c {
                b'"' => in_string = true,
                b'/' if bytes.get(at + 1) == Some(&b'/') => in_comment = true,
                b'{' | b'(' | b'[' => depth += 1,
                b'<' if grammar == Grammar::Schema => depth += 1,
                b'}' | b')' | b']' => depth = depth.saturating_sub(1),
                b'>' if grammar == Grammar::Schema => depth = depth.saturating_sub(1),
                b'i' if grammar == Grammar::Policy
                    && bytes.get(at + 1) == Some(&b'f')
                    && !word(at.checked_sub(1).and_then(|before| bytes.get(before)))
                    && !word(bytes.get(at + 2)) =>
                {
                    ifs += 1;
                }
                _ => {}
            }
            deepest = deepest.max(depth + ifs + chain);
        }
    }
    if deepest > MAX_NESTING {
        return Err(format!(
            "nests {deepest} levels deep, beyond the {MAX_NESTING} a Cedar text may"
        ));
    }

    Ok(())
}

/// Parses one Cedar policy: the nesting bound first, then the official parser on a stack segment
/// sized for that bound.
pub(crate) fn parse_policy(text: &str) -> Result<cedar_policy::Policy, String> {
    check_nesting(text, Grammar::Policy).map_err(|error| format!("cedar: {error}"))?;
    crate::headroom::ample(|| {
        cedar_policy::Policy::from_str(text).map_err(|error| format!("cedar: {error}"))
    })
}

/// The annotation that carries a Cedar policy's alias.
const ALIAS_ANNOTATION: &str = "alias";

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
            // `alias_of` parses the statement, so it is validated there, once.
            policies.push(ExtractedPolicy {
                bytes: slice.as_bytes().to_vec(),
                alias: alias_of(slice)?,
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
pub const SCHEMA_ARTIFACT: &str = permguard_core::domains::artifact::CEDAR_SCHEMA_V1;
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

    /// CEDAR-03: the alias is the parsed annotation. `@alias(` in a comment or inside a string
    /// literal is text, an escaped value decodes to its one canonical form, and a policy that
    /// repeats the annotation or declares an alias outside the identity grammar is refused.
    #[test]
    fn the_alias_is_the_parsed_annotation_and_nothing_that_looks_like_one() {
        let alias = |source: &str| Cedar.declared_alias(source.as_bytes());

        assert_eq!(
            alias("// @alias(\"in-a-comment\")\npermit (principal, action, resource);"),
            Ok(None)
        );
        assert_eq!(
            alias(
                "@id(\"note\")\npermit (principal, action, resource) when { \"@alias(\\\"in-a-string\\\")\" == \"x\" };"
            ),
            Ok(None)
        );
        assert_eq!(
            alias("@alias(\"billing\\u{2d}ro\")\npermit (principal, action, resource);"),
            Ok(Some("billing-ro".to_owned())),
            "an escaped value decodes canonically"
        );
        assert!(
            alias("@alias(\"one\")\n@alias(\"two\")\npermit (principal, action, resource);")
                .is_err(),
            "two aliases are ambiguous"
        );
        for outside in [
            "Billing",
            "billing ro",
            ".billing",
            "billing-",
            "",
            &"a".repeat(129),
        ] {
            let source = format!("@alias(\"{outside}\")\npermit (principal, action, resource);");
            assert!(
                alias(&source).is_err(),
                "`{outside}` is outside the grammar"
            );
        }
        let extracted = Cedar
            .extract(b"// @alias(\"decoy\")\n@alias(\"real-one\")\npermit (principal, action, resource);")
            .expect("extracts");
        assert_eq!(extracted[0].alias.as_deref(), Some("real-one"));
        assert!(
            Cedar
                .extract(b"@alias(\"Not Valid\")\npermit (principal, action, resource);")
                .is_err(),
            "authoring refuses an alias outside the grammar"
        );
    }

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
