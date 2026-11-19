// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! Rego, through Microsoft's `regorus` interpreter.
//!
//! A Rego module is the unit: rules are not standalone, so one file is one
//! policy — the whole verbatim source. The alias rides the standard OPA
//! `# METADATA` annotation block, under `custom.alias`; no bespoke syntax.

#[cfg(feature = "evaluate")]
pub(crate) mod evaluate;
pub(crate) mod parsed;

use permguard_language_core::role::{Authoring, ExtractedPolicy, Language};

/// This language's name, as a manifest's `runtime.language.name` spells it.
pub const NAME: &str = permguard_language_core::names::REGO;

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

/// `regorus`, as `Cargo.lock` pins it: read by the build script, never written by hand.
pub const LOCKED: permguard_language_core::descriptor::Locked =
    permguard_language_core::descriptor::Locked {
        name: "regorus",
        version: env!("PERMGUARD_LOCKED_VERSION"),
        build: env!("PERMGUARD_LOCKED_BUILD"),
    };

/// The Cargo features `regorus` is compiled with, sorted: its upstream default set, spelled out.
///
/// Part of what the descriptor promises: an engine evaluates what its features let it, so a feature
/// added in the workspace manifest is a capability added to every Rego policy. The list equals the
/// dependency declaration exactly, and what Cargo resolves for the whole workspace is exactly what
/// it turns on — `permguard-languages`' `tests/engine_features.rs` fails otherwise.
pub const ENGINE_FEATURES: &[&str] = &[
    "arc",
    "ast",
    "base64",
    "base64url",
    "cache",
    "coverage",
    "glob",
    "graph",
    "hex",
    "http",
    "jsonpatch",
    "jsonschema",
    "net",
    "opa-runtime",
    "regex",
    "rvm",
    "semver",
    "std",
    "time",
    "urlquery",
    "uuid",
    "yaml",
];

/// The language, every engine entry of which is inside the panic boundary: the only way out of
/// this package, so no caller reaches the engine without it.
pub fn language() -> &'static dyn Language {
    &GUARDED
}

/// The evaluating half, every compile of which is inside the same panic boundary.
///
/// Compiled only with this package's `evaluate` feature: a build that validates, as the Control
/// Plane's ingest does, carries no evaluator.
#[cfg(feature = "evaluate")]
pub fn evaluating() -> &'static dyn permguard_language_core::evaluating::Evaluating {
    &GUARDED
}

/// Both halves as one engine: what an application that links this package itself registers with
/// the Data Plane it embeds.
#[cfg(feature = "evaluate")]
pub fn engine() -> permguard_language_core::Engine {
    permguard_language_core::Engine::new(language(), evaluating())
}

/// The language, guarded: the one value both halves hand out.
static GUARDED: permguard_language_core::guard::Guarded<Rego> =
    permguard_language_core::guard::Guarded(Rego);

/// The Rego plugin.
struct Rego;

impl Language for Rego {
    fn name(&self) -> &'static str {
        NAME
    }

    fn language_version(&self) -> &'static str {
        // Rego v1 semantics, as regorus implements them.
        "1.0.0"
    }

    fn engine(&self) -> permguard_language_core::descriptor::Engine {
        use permguard_language_core::descriptor::{Capabilities, Engine, Isolation, IsolationMode};

        Engine {
            locked: crate::LOCKED,
            capabilities: Capabilities {
                features: crate::ENGINE_FEATURES,
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

    fn artifacts(&self) -> &'static [&'static dyn permguard_language_core::artifact::ArtifactType] {
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
        compile_schema(bytes).map(|_| ())
    }

    /// The module parses, calls only allowed built-ins and declares a well-formed alias, if any:
    /// what authoring and the Control Plane's acceptance of a push check, read from the parsed
    /// tree as the load gate reads it.
    fn validate_policy(&self, bytes: &[u8]) -> Result<(), String> {
        let text = std::str::from_utf8(bytes)
            .map_err(|_| "a Rego module must be valid UTF-8".to_owned())?;
        let module = parsed::parse(text)?;
        parsed::check_builtins(&module)?;
        parsed::check_decision_rules(&module)?;
        parsed::check_set(&[("this policy", &module)])?;
        parsed::alias(text, &module).map(|_| ())
    }
    /// Rego's marker is `# METADATA` with `custom.alias`, above the package.
    /// Refuses a partition whose policies share a package.
    ///
    /// Run at authoring and at commit acceptance, where the error belongs to whoever wrote it —
    /// the compile refuses the same shape, so a ledger that reached a plane is refused there too,
    /// but by then the error belongs to whoever met it. See [`shared_package`] for why it
    /// is a refusal rather than something to work around.
    fn validate_set(
        &self,
        policies: &[(&str, &[u8])],
        schema: Option<&[u8]>,
    ) -> Result<(), String> {
        let _ = schema;
        let mut claimed: std::collections::BTreeMap<String, &str> =
            std::collections::BTreeMap::new();
        let mut modules = Vec::new();
        for (name, source) in policies {
            // The package the parser reports, the value the compile and the load gate use too
            // (REGO-07): never a second, lexical reading of it.
            let text = std::str::from_utf8(source)
                .map_err(|_| format!("rego: policy {name} is not valid UTF-8"))?;
            let module =
                parsed::parse(text).map_err(|error| format!("rego: policy {name}: {error}"))?;
            parsed::check_decision_rules(&module)
                .map_err(|error| format!("rego: policy {name}: {error}"))?;
            if let Some(first) = claimed.get(&module.package) {
                return Err(shared_package(&module.package, first, name));
            }
            claimed.insert(module.package.clone(), name);
            modules.push((*name, module));
        }
        // No policy writes into another's package, and no chain of rules outgrows the evaluator
        // (BUG-0018, BUG-0236).
        let held: Vec<(&str, &parsed::Parsed)> = modules
            .iter()
            .map(|(name, module)| (*name, module))
            .collect();
        parsed::check_set(&held)
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

impl permguard_language_core::artifact::ArtifactType for SchemaArtifact {
    fn name(&self) -> &'static str {
        SCHEMA_ARTIFACT
    }

    fn media_type(&self) -> &'static str {
        SCHEMA_MEDIA_TYPE
    }

    fn runtime(&self) -> &'static str {
        NAME
    }

    fn role(&self) -> permguard_language_core::artifact::ArtifactRole {
        permguard_language_core::artifact::ArtifactRole::Schema
    }

    fn semantic_role(&self) -> &'static str {
        "schema"
    }

    fn extensions(&self) -> &'static [&'static str] {
        &[SCHEMA_EXTENSION]
    }

    fn cardinality(&self) -> permguard_language_core::artifact::Cardinality {
        permguard_language_core::artifact::Cardinality::ZeroOrOne
    }

    fn validate(&self, bytes: &[u8]) -> Result<(), String> {
        permguard_language_core::role::Language::validate_schema(&Rego, bytes)
    }
}

/// The registered type of a Rego partition's whole-input schema.
pub struct InputSchemaArtifact;

impl permguard_language_core::artifact::ArtifactType for InputSchemaArtifact {
    fn name(&self) -> &'static str {
        INPUT_SCHEMA_ARTIFACT
    }

    fn media_type(&self) -> &'static str {
        INPUT_SCHEMA_MEDIA_TYPE
    }

    fn runtime(&self) -> &'static str {
        NAME
    }

    fn role(&self) -> permguard_language_core::artifact::ArtifactRole {
        permguard_language_core::artifact::ArtifactRole::Schema
    }

    fn semantic_role(&self) -> &'static str {
        "input-schema"
    }

    fn extensions(&self) -> &'static [&'static str] {
        &[INPUT_SCHEMA_EXTENSION]
    }

    fn cardinality(&self) -> permguard_language_core::artifact::Cardinality {
        permguard_language_core::artifact::Cardinality::ZeroOrOne
    }

    fn validate(&self, bytes: &[u8]) -> Result<(), String> {
        compile_schema(bytes).map(|_| ())
    }
}

/// Compiles a partition's JSON Schema, once.
///
/// Draft 2020-12, and **local**: `$ref` may only reach inside the document. There is no retriever
/// configured, so a schema naming a remote reference fails to compile rather than reaching for the
/// network — a policy load that made an outbound request would be a policy load an operator cannot
/// reason about, and one an attacker could aim.
pub(crate) fn compile_schema(bytes: &[u8]) -> Result<jsonschema::Validator, String> {
    let text =
        std::str::from_utf8(bytes).map_err(|_| "rego: the schema is not valid UTF-8".to_owned())?;
    let document: serde_json::Value = serde_json::from_str(text)
        .map_err(|error| format!("rego: the schema is not JSON: {error}"))?;

    jsonschema::options()
        .with_draft(jsonschema::Draft::Draft202012)
        .build(&document)
        .map_err(|error| format!("rego: the schema is not a usable JSON Schema: {error}"))
}

/// The refusal for two policies that share one package.
///
/// # Why this is refused rather than served
///
/// `package.allow` is the union of every `allow` rule in that package — that is the language, not
/// a detail of this engine. There is no per-file `allow` to evaluate, and no way to ask which
/// file's rule body produced the value.
///
/// So a partition holding two files of one package can be *decided* correctly and cannot be
/// *explained* correctly: evaluating the package rule once per file and attributing the answer to
/// each names policies that decided nothing. The verdict would be right and the reason would be
/// false — and the reason is what an incident response, an appeal and an audit read.
///
/// Permguard cites decisions by policy identity, and a policy identity is a stored unit. Two files
/// of one package are one unit, so they are refused with the two names and the way out: put the
/// package in one file, or give each file its own package.
pub(crate) fn shared_package(package: &str, first: &str, second: &str) -> String {
    format!(
        "rego: the policies {first} and {second} both declare `{package}`. A package's `allow` and \
         `deny` are the union of every rule in it, so this engine can decide them correctly and \
         cannot say which of the two decided — and a decision that cites a policy which decided \
         nothing is a false audit trail. Put the package in one policy, or give each its own \
         package"
    )
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

    /// BUG-0219: a regex that cannot be decided within the backtracking limit fails validation
    /// wherever it sits. Up to `jsonschema` 0.56 it counted as no match, which under `not`, `if`,
    /// `patternProperties` or `propertyNames` let the document through: a schema the engine
    /// cannot finish reading never admits a document.
    #[test]
    fn a_pattern_past_the_backtracking_limit_refuses_the_document_wherever_it_sits() {
        let catastrophic = "^(a|a?)+(?=!)$";
        let long = format!("{}!", "a".repeat(30));
        for (schema, document) in [
            (
                serde_json::json!({"patternProperties": {catastrophic: false}}),
                serde_json::json!({long.clone(): 1}),
            ),
            (
                serde_json::json!({"propertyNames": {"not": {"pattern": catastrophic}}}),
                serde_json::json!({long.clone(): 1}),
            ),
            (
                serde_json::json!({"properties": {"v": {"if": {"pattern": catastrophic}, "then": false}}}),
                serde_json::json!({"v": long.clone()}),
            ),
            (
                serde_json::json!({"properties": {"v": {"not": {"pattern": catastrophic}}}}),
                serde_json::json!({"v": long.clone()}),
            ),
            (
                serde_json::json!({"properties": {"v": {"oneOf": [{"pattern": catastrophic}, {"type": "string"}]}}}),
                serde_json::json!({"v": long.clone()}),
            ),
            (
                serde_json::json!({"properties": {"v": {"type": "string", "pattern": catastrophic}}}),
                serde_json::json!({"v": long.clone()}),
            ),
        ] {
            let validator = compile_schema(schema.to_string().as_bytes()).expect("it compiles");
            assert!(
                validator.validate(&document).is_err(),
                "fail-closed: {schema} admitted {document}"
            );
        }
    }

    /// BUG-0219: patterns are ECMA-262 regular expressions, as JSON Schema specifies them. Pinned
    /// so a dependency bump that changes what a stored schema admits fails here, and is written
    /// in the CHANGELOG, rather than changing answers unseen.
    #[test]
    fn patterns_are_read_as_ecma_262() {
        let admits = |pattern: &str, value: &str| {
            compile_schema(
                serde_json::json!({"properties": {"v": {"type": "string", "pattern": pattern}}})
                    .to_string()
                    .as_bytes(),
            )
            .expect("it compiles")
            .is_valid(&serde_json::json!({"v": value}))
        };
        // `\s` is ECMA-262 white space and line terminators, U+2028 and U+2029 included.
        assert!(admits("^\\s$", " "));
        assert!(admits("^\\s$", "\u{2028}"));
        assert!(admits("^\\s$", "\u{2029}"));
        assert!(!admits("^\\s$", "a"));
        // `[[:alpha:]]` is a bracket expression of `[`, `:`, `a`, `l`, `p`, `h`, then one or
        // more `]`, never a POSIX class.
        assert!(!admits("^[[:alpha:]]+$", "abc"));
        assert!(admits("^[[:alpha:]]+$", "a]"));
    }
}
