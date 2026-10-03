// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! What a language is, in one immutable object, and the digest that names it.
//!
//! # Why one object
//!
//! A manifest's language constraint, the compiled-partition cache, and a decision's reproducibility
//! all depend on *which* runtime answered: its semantics, the exact engine build, what that build
//! can reach, and the limits it enforces. Spread across a trait's methods, those facts drifted —
//! Cedar advertised `4.12.0` while the lock held `cedar-policy 4.11.0`. The descriptor gathers them,
//! and its digest changes exactly when one of them does: an engine upgrade, a feature turned on, a
//! limit added.
//!
//! # Where each member comes from
//!
//! | Member                                                        | Source                                                 |
//! | ------------------------------------------------------------- | ------------------------------------------------------ |
//! | `name`, `language_version`, `experimental`                    | the [`Language`] itself                                |
//! | `engine_name`, `engine_version`, `engine_build`               | `Cargo.lock`, read by `build.rs` ([`locked`])          |
//! | `evaluation_interfaces`                                       | whether the runtime is temporal                        |
//! | `media_types`, `artifacts`, `inputs`                          | the artifact and input registries                      |
//! | `capabilities`, `limits` (the runtime's own), `isolation`     | [`Language::engine`]                                   |
//! | `limits` (the evaluation path's)                              | [`COMMON_LIMITS`], enforced for every runtime          |
//!
//! # The digest
//!
//! `sha256:` followed by the lowercase hex SHA-256 of `permguard.language.descriptor.v1\n` and the
//! RFC 8785 canonical JSON of the descriptor, a closed object with exactly the members above.

use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::sync::LazyLock;

use serde::Serialize;
use sha2::{Digest as _, Sha256};

use crate::role::Language;

/// One engine's identity, as `Cargo.lock` pins it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Locked {
    /// The crate's name.
    pub name: &'static str,
    /// The locked version.
    pub version: &'static str,
    /// `sha256:` and the hex SHA-256 of the engine's whole locked dependency closure, so an update
    /// anywhere beneath the engine is a different build.
    pub build: &'static str,
}

/// The engines this build links, read out of `Cargo.lock` by `build.rs`. Never written by hand.
pub mod locked {
    use super::Locked;

    /// `cedar-policy`.
    pub const CEDAR: Locked = Locked {
        name: "cedar-policy",
        version: env!("PERMGUARD_LOCKED_CEDAR_VERSION"),
        build: env!("PERMGUARD_LOCKED_CEDAR_BUILD"),
    };
    /// `regorus`.
    pub const REGO: Locked = Locked {
        name: "regorus",
        version: env!("PERMGUARD_LOCKED_REGO_VERSION"),
        build: env!("PERMGUARD_LOCKED_REGO_BUILD"),
    };
    /// `amzn-dogwood-language`.
    pub const DOGWOOD: Locked = Locked {
        name: "amzn-dogwood-language",
        version: env!("PERMGUARD_LOCKED_DOGWOOD_VERSION"),
        build: env!("PERMGUARD_LOCKED_DOGWOOD_BUILD"),
    };
}

/// What an engine build could reach. A boolean is `true` whenever the build could reach the
/// capability, so a declaration errs toward more, never toward less.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Capabilities {
    /// The Cargo features the engine is compiled with.
    pub features: &'static [&'static str],
    /// The language extensions policies may use.
    pub extensions: &'static [&'static str],
    /// Whether a policy could read the wall clock.
    pub clock: bool,
    /// Whether a policy could draw a random value.
    pub randomness: bool,
    /// Whether a policy could reach a file, the network, a process or the environment.
    pub io: bool,
}

/// Where a runtime's evaluations run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum IsolationMode {
    /// In this process, bounded by in-process limits.
    InProcess,
    /// In a supervised local worker process with OS limits and kill-on-deadline.
    SupervisedWorker,
}

/// Where a runtime's evaluations run, and why.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Isolation {
    pub mode: IsolationMode,
    pub reason: &'static str,
}

/// What a language states about its engine: the facts no registry can derive.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Engine {
    pub locked: Locked,
    pub capabilities: Capabilities,
    /// The limits this runtime enforces beyond [`COMMON_LIMITS`].
    pub limits: &'static [&'static str],
    pub isolation: Isolation,
}

/// The limits the shared evaluation path enforces for every stateless runtime
/// (`crate::evaluate::evaluate_all` and `crate::headroom`).
pub const COMMON_LIMITS: &[&str] = &[
    "deadline_after_evaluation",
    "deadline_before_evaluation",
    "panic_boundary",
    "stack_headroom",
];

/// The limits every temporal runtime gets from the paths that enter it: a panic boundary around
/// each check, apply and rebuild, and stack headroom. Not the evaluation deadline, which the
/// temporal submission path does not keep (DOGWOOD-03): a descriptor never declares more than it
/// enforces.
pub const TEMPORAL_COMMON_LIMITS: &[&str] = &["panic_boundary", "stack_headroom"];

/// One evaluation interface the runtime implements.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Interface {
    pub id: String,
    pub role: InterfaceRole,
}

/// What a runtime is to an interface.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum InterfaceRole {
    /// It answers a request from the request alone.
    Evaluator,
    /// It checks, records and decides ordered occurrences against a history.
    Temporal,
}

/// The descriptor's `capabilities` member.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CapabilitySet {
    pub features: Vec<String>,
    pub extensions: Vec<String>,
    pub clock: bool,
    pub randomness: bool,
    pub io: bool,
}

/// The descriptor's `isolation` member.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct IsolationSet {
    pub mode: IsolationMode,
    pub reason: String,
}

/// One language, as an immutable object: the closed member set of the languages model.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Descriptor {
    pub name: String,
    pub language_version: String,
    pub engine_name: String,
    pub engine_version: String,
    pub engine_build: String,
    pub experimental: bool,
    pub evaluation_interfaces: Vec<Interface>,
    pub media_types: Vec<String>,
    pub artifacts: Vec<String>,
    pub inputs: Vec<String>,
    pub capabilities: CapabilitySet,
    pub limits: Vec<String>,
    pub isolation: IsolationSet,
}

impl Descriptor {
    /// The descriptor of `language`, assembled from what it states and what the registries hold.
    pub fn of(language: &dyn Language) -> Self {
        let engine = language.engine();
        let name = language.name();

        let mut media_types = BTreeSet::new();
        media_types.insert(language.policy_media_type().to_owned());
        media_types.extend(language.schema_media_type().map(ToOwned::to_owned));
        let mut artifacts = BTreeSet::new();
        for artifact in language.artifacts() {
            media_types.insert(artifact.media_type().to_owned());
            artifacts.insert(artifact.name().to_owned());
        }
        let inputs: BTreeSet<String> = crate::input::input_types()
            .iter()
            .filter(|input| input.runtime() == name)
            .map(|input| input.name().to_owned())
            .collect();
        let common = if language.is_temporal() {
            TEMPORAL_COMMON_LIMITS
        } else {
            COMMON_LIMITS
        };
        let limits: BTreeSet<String> = common
            .iter()
            .chain(engine.limits)
            .map(|limit| (*limit).to_owned())
            .collect();
        let interface = if language.is_temporal() {
            Interface {
                id: permguard_objects::manifest::PROFILE_PDP_TEMPORAL_V1ALPHA1.to_owned(),
                role: InterfaceRole::Temporal,
            }
        } else {
            Interface {
                id: crate::request::INTERFACE.to_owned(),
                role: InterfaceRole::Evaluator,
            }
        };

        Self {
            name: name.to_owned(),
            language_version: language.language_version().to_owned(),
            engine_name: engine.locked.name.to_owned(),
            engine_version: engine.locked.version.to_owned(),
            engine_build: engine.locked.build.to_owned(),
            experimental: language.experimental(),
            evaluation_interfaces: vec![interface],
            media_types: media_types.into_iter().collect(),
            artifacts: artifacts.into_iter().collect(),
            inputs: inputs.into_iter().collect(),
            capabilities: CapabilitySet {
                features: sorted(engine.capabilities.features),
                extensions: sorted(engine.capabilities.extensions),
                clock: engine.capabilities.clock,
                randomness: engine.capabilities.randomness,
                io: engine.capabilities.io,
            },
            limits: limits.into_iter().collect(),
            isolation: IsolationSet {
                mode: engine.isolation.mode,
                reason: engine.isolation.reason.to_owned(),
            },
        }
    }

    /// The descriptor as the closed JSON object the digest is computed over.
    pub fn to_json(&self) -> serde_json::Value {
        // Every member is a string, a boolean, an array or an object of those: serialisation
        // cannot fail, and a value that could not be serialised would be a bug in this file.
        serde_json::to_value(self).unwrap_or(serde_json::Value::Null)
    }

    /// The descriptor's RFC 8785 bytes, or why it has none. Checked for every carried language at
    /// startup (`registry::check_registry`), so [`Descriptor::digest`] never meets a refusal.
    pub fn canonical(&self) -> Result<Vec<u8>, String> {
        let value = serde_json::to_value(self).map_err(|error| error.to_string())?;
        permguard_stream::jcs::canonicalize(&value).map_err(|error| format!("{error:?}"))
    }

    /// The canonical digest: `sha256:` and the hex SHA-256 of the domain and the RFC 8785 bytes.
    pub fn digest(&self) -> String {
        // The descriptor holds no number, so canonicalisation has nothing it can refuse — and the
        // startup check proves it for every carried language.
        let canonical = self.canonical().unwrap_or_default();
        let mut hasher = Sha256::new();
        hasher.update(permguard_core::domains::digest::LANGUAGE_DESCRIPTOR.as_bytes());
        hasher.update(&canonical);
        let digest = hasher.finalize();

        let mut text = String::with_capacity(7 + 64);
        text.push_str("sha256:");
        for byte in digest {
            // Writing to a `String` cannot fail.
            let _ = write!(text, "{byte:02x}");
        }
        text
    }
}

fn sorted(items: &[&str]) -> Vec<String> {
    let set: BTreeSet<&str> = items.iter().copied().collect();
    set.into_iter().map(ToOwned::to_owned).collect()
}

/// Every carried language's descriptor and digest, computed once.
static DIGESTS: LazyLock<Vec<(&'static str, Descriptor, String)>> = LazyLock::new(|| {
    crate::lookup::languages()
        .iter()
        .map(|language| {
            let descriptor = Descriptor::of(*language);
            let digest = descriptor.digest();
            (language.name(), descriptor, digest)
        })
        .collect()
});

/// The descriptor of the carried language `name`.
pub fn descriptor(name: &str) -> Option<&'static Descriptor> {
    DIGESTS
        .iter()
        .find(|(held, _, _)| *held == name)
        .map(|(_, descriptor, _)| descriptor)
}

/// The descriptor digest of the carried language `name`: what a compiled-partition cache key
/// names the runtime by, so a program compiled by another engine build is never served.
pub fn descriptor_digest(name: &str) -> Option<&'static str> {
    DIGESTS
        .iter()
        .find(|(held, _, _)| *held == name)
        .map(|(_, _, digest)| digest.as_str())
}
