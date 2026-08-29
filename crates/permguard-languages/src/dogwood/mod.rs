// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! Dogwood, through Amazon's `amzn-dogwood-language` crate.
//!
//! # What Dogwood adds, and what Permguard adds around it
//!
//! Dogwood is Cedar plus *history*: a policy may ask what has happened recently — `formerly`,
//! `since`, aggregations over a window — as well as what is being asked now. Upstream supplies the
//! language, its lowering to Cedar, validation and the per-request authorizer. Permguard supplies
//! everything a production deployment needs around that: the policy lifecycle, multi-tenancy,
//! durable event history, provenance, replication, APIs, limits and operational safety.
//!
//! Upstream is explicit that its included interpreter is a **reference** implementation and not
//! for production. That is not a caveat to repeat and move past — it is the list of things this
//! integration has to close, and each one is answered somewhere in this crate or in the planes:
//! timestamps validated rather than trusted, the caller's identity bound server-side, the event
//! history durable and bounded rather than in-memory and unbounded, and diagnostics sanitized
//! before they reach a tenant.
//!
//! # The provider sandbox is upstream's, and this build's job is not to weaken it
//!
//! Provider scripts run in upstream's Rhai engine, and the limits are enforced there rather than
//! here — said plainly, because claiming Permguard sandboxes them would take credit for somebody
//! else's guarantee and imply a second set of limits that does not exist. Upstream builds a bare
//! `Engine::new_raw()` carrying only deterministic packages, and bounds operations, call depth,
//! module loading (none) and the size of any string, array or map a script may build.
//!
//! What this build contributes is not weakening it: the dependency is taken with
//! `default-features = false, features = []`, so the optional `net` feature — which registers a
//! networked `http_get` and makes provider evaluation non-deterministic — is off. A provider here
//! cannot reach the network, read a clock, or load another module.
//!
//! What neither side enforces is a **wall-clock timeout**: the operation bound limits work rather
//! than time, so the request deadline the decision path already carries is what bounds how long a
//! provider may take. Stated rather than papered over, because "sandboxed" reads as "and it cannot
//! take too long", and that half is the deadline's doing.
//!
//! # A partition is a bundle, not a file
//!
//! Cedar and Rego partitions are "policies, and at most one schema". A Dogwood partition is a set
//! of *typed artifacts*: a required Cedar action schema, an optional event schema, an optional
//! macro library, optional provider declarations and the provider programs those name. Two of them
//! are `.dw` — the same extension as a policy — so the walk asks
//! [`crate::artifact`] rather than guessing from a name.

pub mod artifacts;
pub(crate) mod compiled;
pub mod occurrence;
pub mod value;

use crate::artifact::ArtifactType;
use crate::role::{Authoring, ExtractedPolicy, Language};

/// This language's name, as a manifest's `runtimes.<key>.language.name` spells it.
pub const NAME: &str = "dogwood";

/// The registered media type of a Dogwood policy.
pub const POLICY_MEDIA_TYPE: &str = "application/vnd.permguard.policy.dogwood";

/// The Dogwood plugin.
pub struct Dogwood;

impl Language for Dogwood {
    fn name(&self) -> &'static str {
        NAME
    }

    fn language_version(&self) -> &'static str {
        // The reviewed upstream revision publishes `1.0.0`.
        "1.0.0"
    }

    /// Dogwood's wire and replication contracts are `v1alpha1`.
    fn experimental(&self) -> bool {
        true
    }

    fn policy_media_type(&self) -> &'static str {
        POLICY_MEDIA_TYPE
    }

    /// None: a Dogwood partition has *several* schemas, and which one is meant is a question
    /// `schema: bool` cannot answer. They are declared as typed artifacts instead.
    fn schema_media_type(&self) -> Option<&'static str> {
        None
    }

    fn artifacts(&self) -> &'static [&'static dyn ArtifactType] {
        artifacts::all()
    }

    fn validate_policy(&self, bytes: &[u8]) -> Result<(), String> {
        let source = source_of(bytes, "a Dogwood policy")?;
        // Parsed against the *default* service schema, which is all a single blob can be checked
        // against: whether it parses at all, and whether its macros resolve. Whether it lowers and
        // type-checks against this partition's own schemas is a question about the set, and
        // `validate_set` is where the set is asked.
        let service = dogwood_language::ServiceSchema::defaults();

        dogwood_language::ParsedPolicySet::parse(source, &service)
            .map(|_| ())
            .map_err(|error| format!("dogwood: {error}"))
    }

    /// The alias a Dogwood policy declares — Cedar's own `@id("…")` annotation, which Dogwood
    /// inherits and which its own examples use as the policy's handle.
    fn declared_alias(&self, source: &[u8]) -> Option<String> {
        let text = std::str::from_utf8(source).ok()?;

        alias_of(text)
    }

    fn authoring(&self) -> Option<&dyn Authoring> {
        Some(self)
    }

    /// Validates the partition as Dogwood itself will: lowered as one set, against every artifact.
    ///
    /// Not `validate_set`, which asks about "the schema": a Dogwood partition has an action schema
    /// *and* an event schema *and* possibly macros and providers, and lowering against a subset
    /// would accept a set the plane then refuses at load — the error belonging to whoever pushed
    /// it, discovered by whoever met it.
    fn validate_bundle(
        &self,
        partition: &str,
        policies: &[(&str, &[u8])],
        artifacts: &std::collections::BTreeMap<String, Vec<u8>>,
        declared: &permguard_objects::manifest::Partition,
    ) -> Result<(), String> {
        let mut bundle = crate::artifact::Artifacts::default();
        for held in artifacts::all().iter().copied() {
            let Some(bytes) = artifacts.get(held.name()) else {
                continue;
            };
            bundle.insert(
                held,
                crate::artifact::ArtifactBlob {
                    name: held.canonical_filename().unwrap_or(held.name()).to_owned(),
                    media_type: held.media_type().to_owned(),
                    data: bytes.clone(),
                },
            );
        }
        let stored: Vec<crate::evaluate::StoredPolicy> = policies
            .iter()
            .map(|(name, bytes)| crate::evaluate::StoredPolicy {
                id: (*name).to_owned(),
                alias: None,
                source: bytes.to_vec(),
            })
            .collect();

        // The compile *is* the check: it parses, lowers and validates exactly as a plane does, so
        // a set that passes here is a set that loads there.
        let compiled = crate::evaluate::Evaluating::compile(self, &stored, &bundle)?;

        // And the manifest's own claim about this partition's history, against what the schemas
        // turned out to say. Run here, where the author can still fix it, as well as at load.
        match compiled.temporal() {
            Some(temporal) => crate::temporal::check_history_scope(
                partition,
                declared.history,
                temporal.contract(),
            ),
            None => Ok(()),
        }
    }

    /// Yes: a Dogwood policy decides against what has already happened.
    fn is_temporal(&self) -> bool {
        true
    }

    fn evaluating(&self) -> Option<&dyn crate::evaluate::Evaluating> {
        Some(self)
    }
}

/// The `@id("…")` annotation above a policy, when it carries one.
///
/// Read line by line rather than with a regular expression over the whole source: an `@id` inside
/// a string literal in the body of a policy is not that policy's identity, and a scan that did not
/// care where it looked would find it.
fn alias_of(text: &str) -> Option<String> {
    for line in text.lines() {
        let line = line.trim();
        if line.starts_with("//") {
            continue;
        }
        let Some(rest) = line.strip_prefix("@id(") else {
            // The annotation precedes the policy head; once the head starts, there is none.
            if line.starts_with("permit") || line.starts_with("forbid") {
                return None;
            }

            continue;
        };
        let inner = rest.strip_suffix(')')?.trim();
        let alias = inner.strip_prefix('"')?.strip_suffix('"')?;
        if alias.is_empty() {
            return None;
        }

        return Some(alias.to_owned());
    }

    None
}

/// The bytes as Dogwood source, or the refusal.
pub(crate) fn source_of<'a>(bytes: &'a [u8], what: &str) -> Result<&'a str, String> {
    std::str::from_utf8(bytes).map_err(|_| format!("dogwood: {what} must be valid UTF-8"))
}

impl Authoring for Dogwood {
    fn file_extensions(&self) -> &'static [&'static str] {
        &["dw"]
    }

    fn schema_file_extensions(&self) -> &'static [&'static str] {
        &["cedarschema", "dwschema"]
    }

    fn extract(&self, source: &[u8]) -> Result<Vec<ExtractedPolicy>, String> {
        self.validate_policy(source)?;
        let text = source_of(source, "a Dogwood policy")?;

        // One file is one policy set, and Permguard stores it whole. Dogwood lowers a file as a
        // unit — a macro or an `@id` applies within it — so splitting it would change what the
        // partition means.
        Ok(vec![ExtractedPolicy {
            bytes: source.to_vec(),
            alias: alias_of(text),
        }])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const POLICY: &str = r#"// A comment mentioning @id("not-the-alias").
@id("read_login_not_logout")
permit (
    principal,
    action == Drupe::Action::"Read",
    resource
)
when temporal {
    formerly within 1h Drupe::Action::"Login"::response{ input.user: context.input.user }
};
"#;

    #[test]
    fn a_policy_parses_and_carries_the_alias_its_author_wrote() {
        let extracted = Dogwood.extract(POLICY.as_bytes()).expect("it parses");

        assert_eq!(extracted.len(), 1, "a file is one policy set");
        assert_eq!(extracted[0].alias.as_deref(), Some("read_login_not_logout"));
        assert_eq!(extracted[0].bytes, POLICY.as_bytes(), "stored verbatim");
    }

    #[test]
    fn an_id_inside_a_comment_is_not_the_alias() {
        // The comment above the annotation names something else on purpose.
        assert_eq!(alias_of(POLICY).as_deref(), Some("read_login_not_logout"));

        let unannotated = "permit (principal, action, resource) when { true };\n";
        assert_eq!(alias_of(unannotated), None);
    }

    #[test]
    fn a_source_dogwood_cannot_parse_is_refused() {
        assert!(Dogwood.validate_policy(b"permit (principal").is_err());
        assert!(Dogwood.validate_policy(&[0xff, 0xfe]).is_err());
    }

    #[test]
    fn the_language_declares_no_single_schema_and_several_artifacts_instead() {
        assert_eq!(Dogwood.schema_media_type(), None);
        assert!(
            Dogwood.artifacts().len() >= 2,
            "a Dogwood partition is a bundle"
        );
    }
}
