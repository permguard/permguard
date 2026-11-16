// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! What a partition may hold, as a registry rather than a pair of media types.
//!
//! # Why one schema was never going to be enough
//!
//! A partition used to be "policies, and at most one schema", and the manifest said so with
//! `schema: bool`. That held while every runtime had one optional schema. It stops holding the
//! moment a runtime needs several *different* fixed artifacts — a required action schema, an
//! optional event schema, a macro library, provider declarations and the provider programs those
//! declarations name — because "is there a schema" cannot distinguish them, and neither can a file
//! extension: two of those are `.dw`, the same extension as a policy.
//!
//! The alternative to a registry is a switch on file names somewhere in the CLI's walk and another
//! one in the plane's loader, which is two places to disagree about what a ledger holds.
//!
//! # What a registered artifact type fixes
//!
//! Everything an author cannot choose: which runtime owns it, what part it plays, how many of it a
//! partition may hold, which extensions carry it, the canonical file name where an extension alone
//! is ambiguous, and how one blob is validated. A manifest names the type; the registry answers
//! the rest. An author who could redefine cardinality could declare two action schemas, and
//! nothing downstream would know which one a policy was validated against.

use crate::role::Language;

/// One artifact of a partition, as the commit holds it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArtifactBlob {
    /// The name the tree entry carries — the file an author wrote. Reported in diagnostics, so a
    /// message about an artifact names the thing on disk rather than a digest.
    pub name: String,
    /// The media type it was stored under, which is what decided its type.
    pub media_type: String,
    /// The verbatim bytes. Never re-rendered: what was authored, signed and stored is what the
    /// runtime compiles.
    pub data: Vec<u8>,
}

/// The non-policy artifacts one partition carries, by registered type.
///
/// The generalisation of the single `Option<Vec<u8>>` schema a partition used to hold. A runtime
/// asks for what it needs by registered name; asking for a type it does not own yields nothing,
/// which is what it should, because the walk refuses an artifact of a foreign runtime before it
/// ever gets here.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Artifacts {
    held: std::collections::BTreeMap<&'static str, Vec<ArtifactBlob>>,
}

impl Artifacts {
    /// Files one blob under its registered type.
    pub fn insert(&mut self, artifact: &'static dyn ArtifactType, blob: ArtifactBlob) {
        self.held.entry(artifact.name()).or_default().push(blob);
    }

    /// The single artifact of that type, when the partition carries one.
    ///
    /// For a `one` or `zero-or-one` type this is the artifact; for a `many` type it is the first,
    /// which is why a `many` type is read through [`Artifacts::all`] instead.
    pub fn one(&self, type_name: &str) -> Option<&ArtifactBlob> {
        self.held.get(type_name).and_then(|held| held.first())
    }

    /// The bytes of the single artifact of that type.
    pub fn bytes(&self, type_name: &str) -> Option<&[u8]> {
        self.one(type_name).map(|blob| blob.data.as_slice())
    }

    /// Every artifact of that type, in the order the walk met them.
    pub fn all(&self, type_name: &str) -> &[ArtifactBlob] {
        self.held
            .get(type_name)
            .map_or(&[][..], |held| held.as_slice())
    }

    /// Every type the partition carries at least one of.
    pub fn types(&self) -> impl Iterator<Item = &'static str> + '_ {
        self.held.keys().copied()
    }

    /// How many artifacts of that type the partition carries.
    pub fn count(&self, type_name: &str) -> usize {
        self.all(type_name).len()
    }

    /// Whether the partition carries nothing at all.
    pub fn is_empty(&self) -> bool {
        self.held.is_empty()
    }

    /// The artifacts of a partition that carries exactly one blob, of the type `artifact`. The
    /// catalogue's `just` resolves a type by its registered name first.
    pub fn just_of(artifact: &'static dyn ArtifactType, data: &[u8]) -> Self {
        let mut artifacts = Self::default();
        artifacts.insert(
            artifact,
            ArtifactBlob {
                name: artifact
                    .canonical_filename()
                    .unwrap_or(artifact.semantic_role())
                    .to_owned(),
                media_type: artifact.media_type().to_owned(),
                data: data.to_vec(),
            },
        );

        artifacts
    }

    /// Roughly how much memory the artifacts hold, for a cache's bounds.
    pub fn footprint(&self) -> usize {
        self.held
            .values()
            .flatten()
            .map(|blob| blob.data.len())
            .sum()
    }
}

/// What part an artifact plays in a partition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArtifactRole {
    /// A rule the engine evaluates. Carries a policy identity and is cited by a decision.
    Policy,
    /// A contract other artifacts and requests are checked against.
    Schema,
    /// Neither: library or declaration material the runtime reads while compiling.
    Support,
}

/// How many of one type a partition may hold.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cardinality {
    /// Exactly one, always.
    One,
    /// At most one.
    ZeroOrOne,
    /// Any number, including none.
    Many,
}

/// One registered artifact type.
///
/// The unit a manifest names and the registry describes. Implemented by the language that owns it,
/// so a runtime's artifacts arrive with the runtime rather than being wired in beside it.
pub trait ArtifactType: Send + Sync {
    /// The registered name, e.g. `permguard.dogwood.action-schema.v1`.
    fn name(&self) -> &'static str;

    /// The media type this artifact is stored under.
    fn media_type(&self) -> &'static str;

    /// The language that owns it. A partition may only declare artifacts of its own runtime.
    fn runtime(&self) -> &'static str;

    /// Policy, schema or support.
    fn role(&self) -> ArtifactRole;

    /// What it is *within* that role — `action-schema`, `event-schema`, `macros`,
    /// `provider-declarations`, `provider-program`. Two schemas of one runtime are told apart by
    /// this and by nothing else.
    fn semantic_role(&self) -> &'static str;

    /// The file extensions an author writes it in.
    fn extensions(&self) -> &'static [&'static str];

    /// The one file name this type is authored under, where its extension is shared.
    ///
    /// Dogwood policies and its macro library are both `.dw`. The registry reserves `macros.dw`
    /// for the library so the walk stays a lookup instead of becoming a guess; anything else with
    /// that extension is a policy.
    fn canonical_filename(&self) -> Option<&'static str> {
        None
    }

    /// How many a partition may hold.
    fn cardinality(&self) -> Cardinality;

    /// Whether a partition of this runtime must carry one, when it declares no contract of its
    /// own. A manifest may require an otherwise optional artifact; it may not excuse a required
    /// one.
    fn required_by_default(&self) -> bool {
        false
    }

    /// Validates one blob of this type on its own.
    ///
    /// Per-blob only: whether the *set* holds together is the language's question, because that is
    /// where an action schema, an event schema and a policy meet.
    fn validate(&self, bytes: &[u8]) -> Result<(), String>;
}

/// The artifacts one language owns.
pub fn artifacts_of(language: &dyn Language) -> &'static [&'static dyn ArtifactType] {
    language.artifacts()
}

/// Which artifact type an authored file is, by name and extension.
///
/// The one place that decision is made. A canonical file name wins over a shared extension, which
/// is what lets `macros.dw` and `policy.dw` live in one directory without the walker knowing that
/// Dogwood exists.
pub fn classify<'a>(
    artifacts: &'a [&'static dyn ArtifactType],
    file_name: &str,
) -> Option<&'a &'static dyn ArtifactType> {
    let extension = file_name.rsplit('.').next()?;

    artifacts
        .iter()
        .find(|held| held.canonical_filename() == Some(file_name))
        .or_else(|| {
            artifacts.iter().find(|held| {
                held.canonical_filename().is_none() && held.extensions().contains(&extension)
            })
        })
}
