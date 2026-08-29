// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The typed artifacts a Dogwood partition holds.
//!
//! # Why these are registry entries and not file-name checks
//!
//! A Dogwood partition needs a required Cedar action schema, and may need an event schema, a macro
//! library, provider declarations and the provider programs those declarations name. Three of
//! those decisions cannot be made from an extension: `.dw` carries both policies and the macro
//! library, and `.cedarschema` and `.dwschema` are two different schemas of one runtime.
//!
//! So each is a registered type with a media type, a role, a cardinality and a validator, and the
//! ones sharing an extension reserve a canonical file name. The CLI's walk and the plane's loader
//! both ask the registry; neither grows a switch that mentions Dogwood.

use crate::artifact::{ArtifactRole, ArtifactType, Cardinality};

/// The registered type of the required Cedar action schema.
pub const ACTION_SCHEMA: &str = "permguard.dogwood.action-schema.v1";
/// The registered type of the optional Dogwood event schema.
pub const EVENT_SCHEMA: &str = "permguard.dogwood.event-schema.v1";
/// The registered type of the optional macro library.
pub const MACROS: &str = "permguard.dogwood.macros.v1";
/// The registered type of the optional provider declarations.
pub const PROVIDERS: &str = "permguard.dogwood.providers.v1";
/// The registered type of one named Rhai provider implementation.
pub const RHAI_PROVIDER: &str = "permguard.dogwood.provider.rhai.v1";

/// The file name reserved for the required Cedar action schema.
pub const ACTION_SCHEMA_FILENAME: &str = "schema.cedarschema";
/// The file name reserved for the optional Dogwood event schema.
pub const EVENT_SCHEMA_FILENAME: &str = "events.dwschema";
/// The file name reserved for the optional macro library. `.dw` otherwise means a policy.
pub const MACROS_FILENAME: &str = "macros.dw";
/// The file name reserved for the optional provider declarations.
pub const PROVIDERS_FILENAME: &str = "providers.json";

/// The required Cedar action schema — Dogwood's `PolicySchema`.
struct ActionSchema;

impl ArtifactType for ActionSchema {
    fn name(&self) -> &'static str {
        ACTION_SCHEMA
    }

    fn media_type(&self) -> &'static str {
        "application/vnd.permguard.dogwood.action-schema"
    }

    fn runtime(&self) -> &'static str {
        super::NAME
    }

    fn role(&self) -> ArtifactRole {
        ArtifactRole::Schema
    }

    fn semantic_role(&self) -> &'static str {
        "action-schema"
    }

    fn extensions(&self) -> &'static [&'static str] {
        &["cedarschema"]
    }

    fn canonical_filename(&self) -> Option<&'static str> {
        Some(ACTION_SCHEMA_FILENAME)
    }

    fn cardinality(&self) -> Cardinality {
        Cardinality::One
    }

    fn required_by_default(&self) -> bool {
        // Without it there is nothing to lower a policy against: every action, entity type and
        // context shape a policy names comes from here.
        true
    }

    /// Validates the action schema by **forcing** the parse Dogwood defers.
    ///
    /// `PolicySchema::from_cedarschema_str` is lazy: it accepts an empty string, a truncated
    /// namespace and outright rubbish, and returns `Ok` for all of them. The schema is not read
    /// until something is lowered against it. A validator built on that call alone would report
    /// every blob as valid — a check that always passes, which is worse than no check, because a
    /// broken schema would then be refused for the first time at load on a serving plane.
    ///
    /// So the parse is provoked here with an **empty** policy source: there is nothing to lower,
    /// so any error that comes back is the schema's own. Verified against upstream: rubbish, a
    /// stray `;`, a truncated namespace and an unresolvable type all fail this way, and a
    /// well-formed schema passes.
    fn validate(&self, bytes: &[u8]) -> Result<(), String> {
        let source = super::source_of(bytes, "an action schema")?;
        let schema = dogwood_language::PolicySchema::from_cedarschema_str(source)
            .map_err(|error| format!("dogwood: the action schema is not usable: {error}"))?;
        let service = dogwood_language::ServiceSchema::defaults();

        dogwood_language::LoweredPolicySet::from_str("", &service, &schema)
            .map(|_| ())
            .map_err(|error| format!("dogwood: the action schema does not parse: {error}"))
    }
}

/// The optional event schema — Dogwood's `ServiceSchema` half.
struct EventSchema;

impl ArtifactType for EventSchema {
    fn name(&self) -> &'static str {
        EVENT_SCHEMA
    }

    fn media_type(&self) -> &'static str {
        "application/vnd.permguard.dogwood.event-schema"
    }

    fn runtime(&self) -> &'static str {
        super::NAME
    }

    fn role(&self) -> ArtifactRole {
        ArtifactRole::Schema
    }

    fn semantic_role(&self) -> &'static str {
        "event-schema"
    }

    fn extensions(&self) -> &'static [&'static str] {
        &["dwschema"]
    }

    fn canonical_filename(&self) -> Option<&'static str> {
        Some(EVENT_SCHEMA_FILENAME)
    }

    fn cardinality(&self) -> Cardinality {
        Cardinality::ZeroOrOne
    }

    fn validate(&self, bytes: &[u8]) -> Result<(), String> {
        let source = super::source_of(bytes, "an event schema")?;

        // Built through the service-schema builder, which is the only thing that can say whether
        // the DSL is well formed: an event schema is not a document that stands on its own.
        dogwood_language::ServiceSchema::builder()
            .event_schema_str(source)
            .build()
            .map(|_| ())
            .map_err(|error| format!("dogwood: the event schema does not build: {error}"))
    }
}

/// The optional macro library. Shares `.dw` with policies, so it reserves a file name.
struct Macros;

impl ArtifactType for Macros {
    fn name(&self) -> &'static str {
        MACROS
    }

    fn media_type(&self) -> &'static str {
        "application/vnd.permguard.dogwood.macros"
    }

    fn runtime(&self) -> &'static str {
        super::NAME
    }

    fn role(&self) -> ArtifactRole {
        ArtifactRole::Support
    }

    fn semantic_role(&self) -> &'static str {
        "macros"
    }

    fn extensions(&self) -> &'static [&'static str] {
        &["dw"]
    }

    fn canonical_filename(&self) -> Option<&'static str> {
        // The one thing that separates a macro library from a policy: both are `.dw`, and an
        // extension cannot tell them apart.
        Some(MACROS_FILENAME)
    }

    fn cardinality(&self) -> Cardinality {
        Cardinality::ZeroOrOne
    }

    fn validate(&self, bytes: &[u8]) -> Result<(), String> {
        let source = super::source_of(bytes, "a macro library")?;

        dogwood_language::ServiceSchema::builder()
            .macros_str(source)
            .build()
            .map(|_| ())
            .map_err(|error| format!("dogwood: the macro library does not build: {error}"))
    }
}

/// The optional provider declarations.
struct Providers;

impl ArtifactType for Providers {
    fn name(&self) -> &'static str {
        PROVIDERS
    }

    fn media_type(&self) -> &'static str {
        "application/vnd.permguard.dogwood.providers"
    }

    fn runtime(&self) -> &'static str {
        super::NAME
    }

    fn role(&self) -> ArtifactRole {
        ArtifactRole::Support
    }

    fn semantic_role(&self) -> &'static str {
        "provider-declarations"
    }

    fn extensions(&self) -> &'static [&'static str] {
        &["json"]
    }

    fn canonical_filename(&self) -> Option<&'static str> {
        Some(PROVIDERS_FILENAME)
    }

    fn cardinality(&self) -> Cardinality {
        Cardinality::ZeroOrOne
    }

    fn validate(&self, bytes: &[u8]) -> Result<(), String> {
        let source = super::source_of(bytes, "provider declarations")?;

        dogwood_language::ProviderDeclarations::from_json(source)
            .map(|_| ())
            .map_err(|error| format!("dogwood: the provider declarations do not parse: {error}"))
    }
}

/// The largest provider script this build will store.
///
/// A bound on what is *kept*, which is a different question from the bounds the sandbox puts on
/// what a script may do while running. A provider is a small pure function over the request; a
/// script measured in hundreds of kilobytes is either not that, or is a way to make a ledger large
/// by pushing to it.
pub const MAX_PROVIDER_SCRIPT_BYTES: usize = 64 * 1024;

/// One named Rhai provider implementation. Any number per partition.
struct RhaiProvider;

impl ArtifactType for RhaiProvider {
    fn name(&self) -> &'static str {
        RHAI_PROVIDER
    }

    fn media_type(&self) -> &'static str {
        "application/vnd.permguard.dogwood.provider.rhai"
    }

    fn runtime(&self) -> &'static str {
        super::NAME
    }

    fn role(&self) -> ArtifactRole {
        ArtifactRole::Support
    }

    fn semantic_role(&self) -> &'static str {
        "provider-program"
    }

    fn extensions(&self) -> &'static [&'static str] {
        &["rhai"]
    }

    fn cardinality(&self) -> Cardinality {
        Cardinality::Many
    }

    fn validate(&self, bytes: &[u8]) -> Result<(), String> {
        // A provider program is untrusted, policy-adjacent code, and what can honestly be checked
        // about one blob on its own is less than it looks.
        //
        // Not that it compiles. This comment used to say it did, and it did not: compiling Rhai
        // needs a Rhai engine, upstream keeps its provider evaluator crate-private, and standing
        // up a second engine here would type-check the script against a *different* build of the
        // language from the one that will run it — which is worse than not checking, because it
        // would pass scripts the real engine rejects and reject ones it accepts. A provider that
        // does not compile is refused at load, by the engine that will run it, naming the script.
        //
        // So: it is text, it is not empty, and it is small enough that storing it is not itself
        // the attack. The limits it *runs* under are upstream's sandbox — see the module
        // documentation in `crate::dogwood`, which says exactly whose they are.
        let source = super::source_of(bytes, "a provider script")?;
        if source.trim().is_empty() {
            return Err("dogwood: a provider script is empty".to_owned());
        }
        if bytes.len() > MAX_PROVIDER_SCRIPT_BYTES {
            return Err(format!(
                "dogwood: a provider script is {} bytes, and the limit is {MAX_PROVIDER_SCRIPT_BYTES}. \
                 A provider is a small pure function over the request; anything this size is doing \
                 something a policy should be doing",
                bytes.len()
            ));
        }

        Ok(())
    }
}

/// Every artifact type Dogwood owns, in a fixed order.
pub fn all() -> &'static [&'static dyn ArtifactType] {
    const ACTION: &ActionSchema = &ActionSchema;
    const EVENT: &EventSchema = &EventSchema;
    const MACROS: &Macros = &Macros;
    const PROVIDERS: &Providers = &Providers;
    const RHAI: &RhaiProvider = &RhaiProvider;

    &[ACTION, EVENT, MACROS, PROVIDERS, RHAI]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::artifact::classify;

    #[test]
    fn the_required_action_schema_is_the_only_required_one() {
        let required: Vec<&str> = all()
            .iter()
            .filter(|artifact| artifact.required_by_default())
            .map(|artifact| artifact.name())
            .collect();

        assert_eq!(required, vec!["permguard.dogwood.action-schema.v1"]);
    }

    /// A macro library and a policy are both `.dw`; only the reserved name separates them.
    #[test]
    fn the_reserved_filename_separates_macros_from_policies() {
        let artifacts: Vec<&'static dyn ArtifactType> = all().to_vec();

        let macros = classify(&artifacts, MACROS_FILENAME).expect("macros.dw is an artifact");
        assert_eq!(macros.name(), "permguard.dogwood.macros.v1");

        // Any other `.dw` is not an artifact of this set — it is a policy, and the walk treats it
        // as one.
        assert!(
            classify(&artifacts, "policy.dw").is_none(),
            "a `.dw` that is not the reserved name is a policy"
        );
    }

    #[test]
    fn each_schema_is_reached_by_its_own_reserved_name() {
        let artifacts: Vec<&'static dyn ArtifactType> = all().to_vec();

        for (file, expected) in [
            (ACTION_SCHEMA_FILENAME, "permguard.dogwood.action-schema.v1"),
            (EVENT_SCHEMA_FILENAME, "permguard.dogwood.event-schema.v1"),
            (PROVIDERS_FILENAME, "permguard.dogwood.providers.v1"),
        ] {
            let found =
                classify(&artifacts, file).unwrap_or_else(|| panic!("{file} is registered"));
            assert_eq!(found.name(), expected);
        }
    }

    /// A provider program has no reserved name — there may be many, each named by its author.
    #[test]
    fn a_provider_program_is_found_by_its_extension() {
        let artifacts: Vec<&'static dyn ArtifactType> = all().to_vec();
        let found = classify(&artifacts, "risk-score.rhai").expect("a `.rhai` is a provider");

        assert_eq!(found.name(), "permguard.dogwood.provider.rhai.v1");
        assert_eq!(found.cardinality(), Cardinality::Many);
    }

    #[test]
    fn every_artifact_validates_a_real_upstream_sample_and_refuses_rubbish() {
        let artifacts: Vec<&'static dyn ArtifactType> = all().to_vec();
        // The action schema's parse is deferred by Dogwood, so these prove the validator forces
        // it. Each refusal below was confirmed against the reviewed upstream revision.
        let action = artifacts[0];
        assert!(
            action
                .validate(b"namespace Drupe { entity Gateway; }")
                .is_ok()
        );
        for rubbish in [
            &b"entity ;;;"[..],
            &b"!!! not a schema ???"[..],
            &b"namespace Drupe { entity Gateway;"[..],
            &b"namespace D { entity G; action \"X\" appliesTo { principal: [Nope], resource: [G] }; }"[..],
        ] {
            assert!(
                action.validate(rubbish).is_err(),
                "a schema Dogwood cannot parse must not pass: {}",
                String::from_utf8_lossy(rubbish)
            );
        }

        // The default event schema Dogwood itself ships must satisfy the event-schema artifact.
        let event = artifacts[1];
        assert!(
            event
                .validate(dogwood_language::DEFAULT_EVENT_SCHEMA.as_bytes())
                .is_ok(),
            "Dogwood's own default event schema must be a legal event schema"
        );
        assert!(event.validate(b"decision event <A>::").is_err());

        // And the default macro library must satisfy the macros artifact.
        let macros = artifacts[2];
        assert!(
            macros
                .validate(dogwood_language::DEFAULT_MACROS.as_bytes())
                .is_ok(),
            "Dogwood's own default macro library must be a legal macro library"
        );

        let providers = artifacts[3];
        assert!(providers.validate(b"not json").is_err());
    }

    /// A provider script is checked for what can honestly be checked about one blob.
    ///
    /// Not compilation: that needs the engine that will run it, and standing up a second one here
    /// would judge the script against a different build of the language. What is checked is that
    /// it is text, that it says something, and that storing it is not itself the attack.
    #[test]
    fn a_provider_script_is_bounded_and_never_claimed_to_be_compiled() {
        let rhai = all()
            .iter()
            .copied()
            .find(|held| held.name() == RHAI_PROVIDER)
            .expect("the registry carries it");

        rhai.validate(b"fn value(request) { request.user }")
            .expect("an ordinary script");

        let empty = rhai
            .validate(b"   \n  ")
            .expect_err("a script that says nothing");
        assert!(empty.contains("empty"), "{empty}");

        let binary = rhai
            .validate(&[0xff, 0xfe, 0xfd])
            .expect_err("a script that is not text");
        assert!(!binary.is_empty());

        let oversize = vec![b'x'; MAX_PROVIDER_SCRIPT_BYTES + 1];
        let refused = rhai
            .validate(&oversize)
            .expect_err("past the storage bound");
        assert!(
            refused.contains(&MAX_PROVIDER_SCRIPT_BYTES.to_string()),
            "the refusal names the bound: {refused}"
        );

        // Right at the bound is accepted: the limit is a limit, not an off-by-one.
        let exact = vec![b'x'; MAX_PROVIDER_SCRIPT_BYTES];
        rhai.validate(&exact).expect("exactly the bound is allowed");

        // Deliberately *not* asserted: that a syntactically broken script is refused here. It is
        // refused at load, by the engine that runs it, and pretending otherwise here is the claim
        // this test exists to keep out of the code.
        rhai.validate(b"fn value(request) { this is not rhai")
            .expect("a broken script is the load gate's refusal, not this one's");
    }
}
