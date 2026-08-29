// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The roles a language plays, one trait each, because the two sides of the
//! product ask a language different things.
//!
//! [`Language`] is the base — what it is called, what it owns on the wire,
//! whether a blob is legal, what alias a source declares. Both the ingest
//! path and the CLI need exactly this, and a third-party language pack must
//! implement it to be usable at all.
//!
//! [`Authoring`] is the CLI's half: turning files an author edits into
//! policies. A server is handed policies; it never reads a source tree, and
//! with the role separated it cannot even reach the splitter.

/// One policy extracted from a source file: its verbatim bytes and the
/// alias its language marker declares, when it declares one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtractedPolicy {
    /// The exact authored bytes of this one policy — what is hashed,
    /// stored, and identity-derived. Never re-rendered.
    pub bytes: Vec<u8>,
    /// The declared alias, when the language marker carries one.
    pub alias: Option<String>,
}

/// A policy language, as **both** sides see it: what it is called, what it
/// owns on the wire, and whether a given blob is legal.
///
/// This is the base role — the one a third-party language pack must
/// implement to be usable at all, and the only one the ingest path needs.
pub trait Language: Send + Sync {
    /// The language name the manifest's `runtimes.<key>.language.name` uses.
    fn name(&self) -> &'static str;

    /// The language version this plugin implements, for the manifest gate.
    fn language_version(&self) -> &'static str;

    /// Whether this runtime's contracts are still provisional.
    ///
    /// A language answers for itself, and the gate asks rather than consulting a list. The list was
    /// the problem: a single `dogwood: bool` meant every layer that carried the opt-in — the
    /// configuration type, the file schema, the gate, the composition roots — had to be edited to
    /// add a second provisional runtime, and each of those edits was a place to forget one.
    ///
    /// Experimental means *serving* it is a deployment's explicit choice. The language is compiled
    /// in either way; what an opt-in buys is a plane that will load and answer for its partitions.
    fn experimental(&self) -> bool {
        false
    }

    /// The registered media type of a policy of this language.
    fn policy_media_type(&self) -> &'static str;

    /// The registered media type of this language's schema, when it has one.
    ///
    /// The legacy one-schema contract. A runtime with several fixed artifacts describes them
    /// through [`Language::artifacts`] instead, and answers `None` here.
    fn schema_media_type(&self) -> Option<&'static str>;

    /// The typed artifacts this runtime owns, when it describes its contents that way.
    ///
    /// Empty for a language whose partitions are "policies and at most one schema" — Cedar and
    /// Rego today. A runtime needing several distinct fixed artifacts registers them here, and
    /// everything downstream asks the registry rather than growing a switch of its own.
    fn artifacts(&self) -> &'static [&'static dyn crate::artifact::ArtifactType] {
        &[]
    }

    /// Validates one policy: it must parse under this language.
    fn validate_policy(&self, bytes: &[u8]) -> Result<(), String>;

    /// Validates one schema, for languages that have one.
    fn validate_schema(&self, bytes: &[u8]) -> Result<(), String> {
        let _ = bytes;
        Err("this language has no schema".to_owned())
    }

    /// Validates a whole partition **as a set**: every policy, against the
    /// schema when the language has one.
    ///
    /// Per-blob validation ([`Language::validate_policy`]) proves each policy
    /// parses; this proves the set is one the data plane will actually serve —
    /// for Cedar, that every policy type-checks against the partition's schema
    /// in strict mode, exactly the check the load gate runs. Run at authoring
    /// and at commit acceptance, because a set that fails it would otherwise
    /// be stored, mirrored, and refused only at load: fail-closed, but the
    /// error belongs to whoever pushed it, not to the plane that met it.
    ///
    /// `policies` pairs each policy's name — the handle an error cites — with
    /// its verbatim bytes. The default accepts: a language with no set-level
    /// semantics has nothing further to check here.
    fn validate_set(
        &self,
        policies: &[(&str, &[u8])],
        schema: Option<&[u8]>,
    ) -> Result<(), String> {
        let _ = (policies, schema);
        Ok(())
    }

    /// Validates a whole partition against **every artifact it carries**.
    ///
    /// The generalisation of [`Language::validate_set`], and the one an authoring walk calls. A
    /// runtime with one schema answers the same question either way; a runtime that lowers its
    /// policies against an action schema *and* an event schema *and* a macro library cannot, and a
    /// check handed one of the three would be checking something no plane will serve.
    ///
    /// `artifacts` maps a registered type name to its verbatim bytes. The default finds this
    /// runtime's single schema in it and defers to `validate_set`, so a language that has one
    /// implements one method rather than two.
    fn validate_bundle(
        &self,
        partition: &str,
        policies: &[(&str, &[u8])],
        artifacts: &std::collections::BTreeMap<String, Vec<u8>>,
        declared: &permguard_objects::manifest::Partition,
    ) -> Result<(), String> {
        // A history scope is a statement about a history, and a language that does not remember
        // has none. Refused rather than ignored: a declaration that does nothing reads, to whoever
        // finds it later, as one that does something.
        if let Some(scope) = declared.history {
            return Err(format!(
                "the partition `{partition}` declares `history: {{ scope: {} }}` and its runtime \
                 `{}` keeps no history. A history scope describes what a temporal evaluation \
                 ranges over; there is nothing here for it to describe",
                scope.as_str(),
                self.name()
            ));
        }
        let schema = self
            .artifacts()
            .iter()
            .find(|held| held.role() == crate::artifact::ArtifactRole::Schema)
            .and_then(|held| artifacts.get(held.name()))
            .map(Vec::as_slice);

        self.validate_set(policies, schema)
    }

    /// The alias this source declares through the language's own marker —
    /// Cedar's `@alias("…")`, Rego's `# METADATA custom.alias`. The ingest
    /// path needs it too: it checks that the annotation mirrors the source.
    fn declared_alias(&self, source: &[u8]) -> Option<String>;

    /// The authoring half, when this build carries it.
    fn authoring(&self) -> Option<&dyn Authoring> {
        None
    }

    /// Whether this runtime's partitions **remember**: whether they decide against a durable
    /// history rather than against the request alone.
    ///
    /// Asked of the language rather than of a compiled partition, because it is needed before
    /// anything is compiled: a manifest names profiles and partitions, and whether the two agree
    /// about which interface they are for has to be answerable at the load gate.
    fn is_temporal(&self) -> bool {
        false
    }

    /// The evaluating half, when this build carries it.
    ///
    /// Asked for, never assumed — exactly like [`Language::authoring`]: a
    /// build that carries a language it cannot evaluate answers `None`, and
    /// the caller refuses the load instead of discovering it mid-decision.
    fn evaluating(&self) -> Option<&dyn crate::evaluate::Evaluating> {
        None
    }
}

/// The authoring role: turning files an author edits into policies.
///
/// The CLI's half, and only the CLI's — a server is handed policies, it
/// never reads a source tree.
pub trait Authoring: Send + Sync {
    /// The file extensions `refresh` reads for this language.
    fn file_extensions(&self) -> &'static [&'static str];

    /// The file extensions that hold this language's **schema**, when it has one.
    ///
    /// Asked of the language rather than spelled out by whoever walks a source tree: `cedarschema`
    /// was hard-coded in the CLI's walk, so adding a schema to a second language meant editing a
    /// file that has no business knowing what Cedar calls things — and forgetting to would have
    /// left the schema sitting there, read by nobody, with the partition reporting that it
    /// declares one and carries none.
    fn schema_file_extensions(&self) -> &'static [&'static str] {
        &[]
    }

    /// Splits a source file into its policies, each with verbatim bytes and
    /// its declared alias. A language whose unit is the file returns one.
    fn extract(&self, source: &[u8]) -> Result<Vec<ExtractedPolicy>, String>;
}
