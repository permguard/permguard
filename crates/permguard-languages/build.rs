// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! Reads every policy engine's locked identity out of the workspace `Cargo.lock`.
//!
//! A language descriptor promises which engine evaluates its policies. Written by hand, that promise
//! drifted: Cedar advertised `4.12.0` while the lock held `cedar-policy 4.11.0`. Read from the lock
//! at build time, it cannot — the binary reports exactly the engine it was linked against, and a
//! lock that does not name one engine exactly once fails the build rather than shipping a guess.
//!
//! For each engine this sets `PERMGUARD_LOCKED_<ENGINE>_VERSION`, the locked version, and
//! `PERMGUARD_LOCKED_<ENGINE>_BUILD`, the build identity: `sha256:` and the hex SHA-256 of the
//! engine's whole locked dependency closure — one line per crate reachable from it,
//! `name version checksum-or-source`, sorted and joined by `\n`. A `cargo update` anywhere beneath
//! an engine changes what it evaluates with, so it changes this too.
//!
//! The lock read is this workspace's own, `../../Cargo.lock`: the crate is `publish = false` and
//! built only inside it, so the lock is the one its binaries were resolved with.

use std::collections::{BTreeSet, VecDeque};
use std::fmt::Write as _;
use std::path::Path;

use sha2::{Digest as _, Sha256};

/// The engines, by crate name, the variable prefix each is published under, and the other crates
/// whose behaviour is part of the runtime: Rego admits its input through `jsonschema`. Those are
/// found through this crate's own entry in the lock, which names the exact version it links when
/// the lock holds several.
const ENGINES: &[(&str, &str, &[&str])] = &[
    ("cedar-policy", "CEDAR", &[]),
    ("regorus", "REGO", &["jsonschema"]),
    ("amzn-dogwood-language", "DOGWOOD", &[]),
];

fn main() {
    let manifest = std::env::var("CARGO_MANIFEST_DIR")
        .unwrap_or_else(|_| fail("CARGO_MANIFEST_DIR is not set"));
    let lock = Path::new(&manifest).join("../../Cargo.lock");
    println!("cargo:rerun-if-changed={}", lock.display());
    println!("cargo:rerun-if-changed=build.rs");

    let text = std::fs::read_to_string(&lock)
        .unwrap_or_else(|error| fail(&format!("cannot read {}: {error}", lock.display())));
    let packages = packages(&text);

    for (name, prefix, also) in ENGINES {
        let found: Vec<usize> = packages
            .iter()
            .enumerate()
            .filter(|(_, package)| package.name == *name)
            .map(|(index, _)| index)
            .collect();
        let [engine] = found.as_slice() else {
            fail(&format!(
                "Cargo.lock names `{name}` {} times; a language descriptor needs exactly one locked engine",
                found.len()
            ));
        };

        println!(
            "cargo:rustc-env=PERMGUARD_LOCKED_{prefix}_VERSION={}",
            packages[*engine].version
        );
        println!(
            "cargo:rustc-env=PERMGUARD_LOCKED_{prefix}_BUILD={}",
            closure_digest(&packages, *engine, also)
        );
    }
}

/// One `[[package]]` entry of the lock: the fields a descriptor reads.
#[derive(Default)]
struct Package {
    name: String,
    version: String,
    source: Option<String>,
    checksum: Option<String>,
    /// As the lock writes them: `name`, `name version` or `name version (source)`.
    dependencies: Vec<String>,
}

impl Package {
    fn line(&self) -> String {
        let build = self
            .checksum
            .as_deref()
            .or(self.source.as_deref())
            .unwrap_or("local");
        format!("{} {} {build}", self.name, self.version)
    }
}

/// The digest of the closure of `root` in the lock's dependency graph.
fn closure_digest(packages: &[Package], root: usize, also: &[&str]) -> String {
    let mut seen = BTreeSet::new();
    let mut queue = VecDeque::from([root]);
    queue.extend(
        also.iter()
            .map(|name| resolve(packages, &own_dependency(packages, name))),
    );
    while let Some(index) = queue.pop_front() {
        if !seen.insert(index) {
            continue;
        }
        for reference in &packages[index].dependencies {
            queue.push_back(resolve(packages, reference));
        }
    }
    let lines: BTreeSet<String> = seen.iter().map(|index| packages[*index].line()).collect();
    let joined = lines.into_iter().collect::<Vec<_>>().join("\n");

    let mut text = String::from("sha256:");
    for byte in Sha256::digest(joined.as_bytes()) {
        let _ = write!(text, "{byte:02x}");
    }
    text
}

/// How this crate's own entry in the lock names its dependency `name`.
fn own_dependency(packages: &[Package], name: &str) -> String {
    let own = packages
        .iter()
        .find(|package| package.name == "permguard-languages")
        .unwrap_or_else(|| fail("Cargo.lock has no entry for permguard-languages"));
    own.dependencies
        .iter()
        .find(|reference| reference.split(' ').next() == Some(name))
        .cloned()
        .unwrap_or_else(|| fail(&format!("permguard-languages does not depend on `{name}`")))
}

/// The package a dependency entry names: by name alone when the lock holds one of that name, by
/// name and version otherwise, and by source too when two share both.
fn resolve(packages: &[Package], reference: &str) -> usize {
    let mut parts = reference.splitn(3, ' ');
    let name = parts.next().unwrap_or_default();
    let version = parts.next();
    let source = parts
        .next()
        .map(|source| source.trim_start_matches('(').trim_end_matches(')'));
    let matching: Vec<usize> = packages
        .iter()
        .enumerate()
        .filter(|(_, package)| package.name == name)
        .filter(|(_, package)| version.is_none_or(|version| package.version == version))
        .filter(|(_, package)| {
            source.is_none_or(|source| package.source.as_deref() == Some(source))
        })
        .map(|(index, _)| index)
        .collect();
    match matching.as_slice() {
        [index] => *index,
        _ => fail(&format!(
            "Cargo.lock's dependency `{reference}` names {} packages",
            matching.len()
        )),
    }
}

/// The lock's packages. The lock format is TOML written by Cargo itself: one `key = "value"` per
/// line inside each `[[package]]` table, and a `dependencies` array of one quoted entry per line.
fn packages(text: &str) -> Vec<Package> {
    let mut packages = Vec::new();
    let mut current: Option<Package> = None;
    let mut in_dependencies = false;
    for line in text.lines() {
        let line = line.trim();
        if in_dependencies {
            if line == "]" {
                in_dependencies = false;
            } else if let (Some(package), Some(entry)) = (
                current.as_mut(),
                line.trim_end_matches(',')
                    .strip_prefix('"')
                    .and_then(|entry| entry.strip_suffix('"')),
            ) {
                package.dependencies.push(entry.to_owned());
            }
            continue;
        }
        if line == "[[package]]" {
            packages.extend(current.take());
            current = Some(Package::default());
            continue;
        }
        if line.starts_with('[') {
            packages.extend(current.take());
            continue;
        }
        if line == "dependencies = [" {
            in_dependencies = true;
            continue;
        }
        let (Some(package), Some((key, value))) = (current.as_mut(), line.split_once(" = ")) else {
            continue;
        };
        let Some(value) = value
            .strip_prefix('"')
            .and_then(|value| value.strip_suffix('"'))
        else {
            continue;
        };
        match key {
            "name" => package.name = value.to_owned(),
            "version" => package.version = value.to_owned(),
            "source" => package.source = Some(value.to_owned()),
            "checksum" => package.checksum = Some(value.to_owned()),
            _ => {}
        }
    }
    packages.extend(current);

    packages
}

fn fail(message: &str) -> ! {
    eprintln!("error: {message}");
    std::process::exit(1)
}
