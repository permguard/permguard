// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The language descriptors, pinned: golden vectors, the digest recomputed independently, and the
//! engine identity read out of `Cargo.lock` by a second, independent reader.
//!
//! A vector changes when a descriptor deliberately does — an engine upgrade, a feature, a limit —
//! and that change is a reviewed edit of `tests/vectors/descriptors.json`, never a silent drift.
//! `engine_build` digests an engine's whole locked dependency closure, so a `cargo update` of any
//! crate beneath an engine changes it too: regenerate the vectors and review the diff.

#![allow(clippy::expect_used)]

use permguard_languages::descriptor::{Descriptor, descriptor, descriptor_digest};
use serde_json::Value;
use sha2::{Digest as _, Sha256};

fn vectors() -> Value {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/vectors/descriptors.json"
    );
    let text = std::fs::read_to_string(path).expect("the vector file is readable");
    serde_json::from_str(&text).expect("the vector file is JSON")
}

const MEMBERS: [&str; 13] = [
    "artifacts",
    "capabilities",
    "engine_build",
    "engine_name",
    "engine_version",
    "evaluation_interfaces",
    "experimental",
    "inputs",
    "isolation",
    "language_version",
    "limits",
    "media_types",
    "name",
];

/// Every carried language has a descriptor equal to its vector, member for member, with exactly
/// the closed member set of the languages model.
#[test]
fn test_every_descriptor_equals_its_golden_vector() {
    let vectors = vectors();
    let languages = vectors["languages"].as_array().expect("languages");
    let carried: Vec<&str> = permguard_languages::languages()
        .iter()
        .map(|language| language.name())
        .collect();
    assert_eq!(
        languages.len(),
        carried.len(),
        "one vector per carried language"
    );

    for vector in languages {
        let expected = &vector["descriptor"];
        let name = expected["name"].as_str().expect("a name");
        let held = descriptor(name).expect("a carried language");

        assert_eq!(&held.to_json(), expected, "`{name}`'s descriptor drifted");
        let mut members: Vec<&str> = expected
            .as_object()
            .expect("an object")
            .keys()
            .map(String::as_str)
            .collect();
        members.sort_unstable();
        assert_eq!(members, MEMBERS, "`{name}`: the closed member set");
    }
}

/// The digest is `sha256:` and the hex SHA-256 of the domain and the RFC 8785 bytes — recomputed
/// here from the vector, not from the descriptor, so the two computations are independent.
#[test]
fn test_every_digest_is_recomputed_from_the_canonical_vector() {
    let vectors = vectors();
    let domain = vectors["domain"].as_str().expect("a domain");
    assert_eq!(
        domain,
        permguard_core::domains::digest::LANGUAGE_DESCRIPTOR,
        "the registered domain"
    );

    for vector in vectors["languages"].as_array().expect("languages") {
        let name = vector["descriptor"]["name"].as_str().expect("a name");
        let canonical =
            permguard_stream::jcs::canonicalize(&vector["descriptor"]).expect("canonical JSON");
        let mut hasher = Sha256::new();
        hasher.update(domain.as_bytes());
        hasher.update(&canonical);
        let recomputed: String = hasher
            .finalize()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();

        assert_eq!(
            vector["digest"].as_str(),
            Some(format!("sha256:{recomputed}").as_str())
        );
        assert_eq!(
            descriptor_digest(name),
            vector["digest"].as_str(),
            "`{name}`: the digest the cache keys use"
        );
    }
}

/// A descriptor that changes in any member changes its digest.
#[test]
fn test_any_change_to_a_descriptor_changes_its_digest() {
    let held = descriptor("rego").expect("carried").clone();
    let mut changed: Descriptor = held.clone();
    changed.limits.push("an_added_limit".to_owned());
    assert_ne!(held.digest(), changed.digest());

    let mut changed = held.clone();
    changed.engine_build.push('0');
    assert_ne!(held.digest(), changed.digest());
}

/// The lock, read by a parser of its own: a second reading of the same file, so the build script
/// and this test would have to be wrong the same way to agree on a wrong value.
/// One package: `(name, version, source, checksum, dependencies)`.
type Locked = (String, String, Option<String>, Option<String>, Vec<String>);

struct Lock {
    packages: Vec<Locked>,
}

impl Lock {
    fn read() -> Self {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../Cargo.lock");
        let lock = std::fs::read_to_string(path)
            .expect("the workspace lock is readable")
            .replace("\r\n", "\n");
        let packages = lock
            .split("\n[[package]]\n")
            .skip(1)
            .map(|block| {
                let block = block.split("\n\n").next().unwrap_or_default();
                let field = |key: &str| {
                    block
                        .lines()
                        .find_map(|line| line.strip_prefix(&format!("{key} = \"")))
                        .map(|value| value.trim_end_matches('"').to_owned())
                };
                let dependencies = block
                    .split_once("dependencies = [\n")
                    .map(|(_, rest)| {
                        rest.lines()
                            .take_while(|line| line.trim() != "]")
                            .map(|line| {
                                line.trim()
                                    .trim_end_matches(',')
                                    .trim_matches('"')
                                    .to_owned()
                            })
                            .collect()
                    })
                    .unwrap_or_default();
                (
                    field("name").expect("a name"),
                    field("version").expect("a version"),
                    field("source"),
                    field("checksum"),
                    dependencies,
                )
            })
            .collect();
        Self { packages }
    }

    fn find(&self, reference: &str) -> usize {
        let parts: Vec<&str> = reference.splitn(3, ' ').collect();
        let matching: Vec<usize> = (0..self.packages.len())
            .filter(|&index| {
                let (name, version, source, _, _) = &self.packages[index];
                name == parts[0]
                    && parts.get(1).is_none_or(|wanted| version == wanted)
                    && parts.get(2).is_none_or(|wanted| {
                        source.as_deref()
                            == Some(wanted.trim_start_matches('(').trim_end_matches(')'))
                    })
            })
            .collect();
        assert_eq!(matching.len(), 1, "`{reference}` names one package");
        matching[0]
    }

    /// The engine's version, and the digest of its closure with the other crates of its runtime.
    fn engine(&self, name: &str, also: &[&str]) -> (String, String) {
        let root = self.find(name);
        let mut seen = std::collections::BTreeSet::new();
        let mut stack = vec![root];
        // The crates beside the engine, as this crate's own lock entry names them.
        let own = self.find("permguard-languages");
        stack.extend(also.iter().map(|other| {
            let reference = self.packages[own]
                .4
                .iter()
                .find(|reference| reference.split(' ').next() == Some(*other))
                .expect("permguard-languages depends on it")
                .clone();
            self.find(&reference)
        }));
        while let Some(index) = stack.pop() {
            if seen.insert(index) {
                stack.extend(
                    self.packages[index]
                        .4
                        .iter()
                        .map(|reference| self.find(reference)),
                );
            }
        }
        let mut lines: Vec<String> = seen
            .iter()
            .map(|&index| {
                let (name, version, source, checksum, _) = &self.packages[index];
                let build = checksum.as_deref().or(source.as_deref()).unwrap_or("local");
                format!("{name} {version} {build}")
            })
            .collect();
        lines.sort();
        lines.dedup();
        let digest: String = Sha256::digest(lines.join("\n").as_bytes())
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();

        (self.packages[root].1.clone(), format!("sha256:{digest}"))
    }
}

/// LANG-02, CEDAR-01: every descriptor's engine is the locked one — its version, and the digest of
/// its whole locked dependency closure — and Cedar's language version is its locked engine's, never
/// a handwritten constant.
#[test]
fn test_every_engine_is_the_one_cargo_lock_pins() {
    let lock = Lock::read();
    for (language, engine, also) in [
        ("cedar", "cedar-policy", &[][..]),
        ("rego", "regorus", &["jsonschema"][..]),
        ("dogwood", "amzn-dogwood-language", &[][..]),
    ] {
        let held = descriptor(language).expect("carried");
        let (version, build) = lock.engine(engine, also);

        assert_eq!(held.engine_name, engine, "`{language}`");
        assert_eq!(held.engine_version, version, "`{language}`");
        assert_eq!(held.engine_build, build, "`{language}`");
    }

    let cedar = descriptor("cedar").expect("carried");
    assert_eq!(
        cedar.language_version, cedar.engine_version,
        "Cedar's language is versioned by its engine"
    );
    let provided = permguard_languages::registry::provided_runtimes();
    let gate = provided
        .iter()
        .find(|runtime| runtime.language_name == "cedar")
        .expect("Cedar is provided");
    assert_eq!(
        gate.language_version.to_string(),
        cedar.language_version,
        "the load gate compares a manifest with the descriptor"
    );
}
