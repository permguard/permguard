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

    /// The registered media type of a policy of this language.
    fn policy_media_type(&self) -> &'static str;

    /// The registered media type of this language's schema, when it has one.
    fn schema_media_type(&self) -> Option<&'static str>;

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

    /// The alias this source declares through the language's own marker —
    /// Cedar's `@alias("…")`, Rego's `# METADATA custom.alias`. The ingest
    /// path needs it too: it checks that the annotation mirrors the source.
    fn declared_alias(&self, source: &[u8]) -> Option<String>;

    /// The authoring half, when this build carries it.
    fn authoring(&self) -> Option<&dyn Authoring> {
        None
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
