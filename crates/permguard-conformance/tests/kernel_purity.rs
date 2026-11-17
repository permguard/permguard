// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The evaluator's kernel, and the language contracts it runs, reach no operating system
//! interface (`11-refactoring/1-dependencies.md`, The evaluator): no thread, file, socket,
//! process, environment, wall clock or asynchronous runtime, outside the one file the kernel's
//! `threads` feature compiles.
//!
//! They read the monotonic clock, in two places named here and nowhere else: the kernel, to
//! measure each evaluation, and the contracts, to tell whether a deadline its caller set has
//! passed. A deadline does change an answer, to `deadline_exceeded`; the kernel's own
//! `Evaluator` sets none, so what it answers depends on no clock.
//!
//! What a build links is `dependency_direction.rs`'s to prove; this reads the sources, because a
//! standard library interface is in no dependency graph. It reads them as text, so it is a guard
//! against drift and not a proof: the forms a path can take are matched, a grouped import and a
//! renamed `std` included, and a macro that wrote one would pass. An engine's own package, and
//! the upstream engine it wraps, are not read. The proof of a target with none of these
//! interfaces is a build for it, which does not exist: the kernel with no engine does not build
//! for `wasm32-unknown-unknown` today, since the object model's cryptography links `getrandom`
//! with no browser backend selected. No such target is claimed.

#![allow(clippy::expect_used)]

use std::path::{Path, PathBuf};

/// The standard library's modules the kernel does not reach.
const NATIVE_MODULES: &[&str] = &["thread", "fs", "net", "process", "env", "os"];

/// What it does not name at all: an asynchronous runtime, the wall clock, and the ways `std`
/// could be reached under another name.
const NEVER_NAMED: &[&str] = &["tokio", "SystemTime", "extern crate", "std as"];

/// The packages read: the kernel, and the contracts it evaluates through.
const READ: &[&str] = &["permguard-evaluator", "permguard-language-core"];

/// Where the monotonic clock is read, and how many times in each file: the kernel measuring an
/// evaluation, the contracts reading what is left of a deadline. Every check of a deadline goes
/// through that one read.
const MONOTONIC: &[(&str, &str, usize)] = &[
    ("permguard-evaluator", "evaluate.rs", 1),
    ("permguard-language-core", "evaluate.rs", 1),
];

/// The one file that starts a thread, compiled only with the `threads` feature.
const THREADS: &str = "fanout/threads.rs";

/// `code` with its line comments removed, so a sentence about a thread is not a thread.
fn uncommented(code: &str) -> String {
    code.lines()
        .map(|line| line.split("//").next().unwrap_or_default())
        .collect::<Vec<_>>()
        .join("\n")
}

/// Whether `word` stands in `text` as a whole identifier.
fn names(text: &str, word: &str) -> bool {
    let boundary = |c: Option<char>| c.is_none_or(|c| !c.is_alphanumeric() && c != '_');
    text.match_indices(word).any(|(at, _)| {
        boundary(text[..at].chars().next_back()) && boundary(text[at + word.len()..].chars().next())
    })
}

/// The native modules `code` reaches: by a path, `std::fs`, or inside a grouped import of `std`,
/// `use std::{fs, io}`, however it is spaced or broken over lines.
fn native_modules(code: &str) -> Vec<&'static str> {
    let compact: String = code.chars().filter(|c| !c.is_whitespace()).collect();
    let mut found = Vec::new();
    for module in NATIVE_MODULES {
        let by_path = compact
            .match_indices(&format!("std::{module}"))
            .any(|(at, matched)| {
                compact[at + matched.len()..]
                    .chars()
                    .next()
                    .is_none_or(|c| !c.is_alphanumeric() && c != '_')
            });
        let grouped = compact.match_indices("std::{").any(|(at, matched)| {
            let group = &compact[at + matched.len()..];
            let group = &group[..group.find('}').unwrap_or(group.len())];
            group
                .split(|c: char| !c.is_alphanumeric() && c != '_')
                .any(|name| name == *module)
        });
        if by_path || grouped {
            found.push(*module);
        }
    }
    found
}

fn sources(directory: &Path, found: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(directory).expect("a source directory") {
        let path = entry.expect("an entry").path();
        if path.is_dir() {
            sources(&path, found);
        } else if path.extension().is_some_and(|extension| extension == "rs") {
            found.push(path);
        }
    }
}

#[test]
fn test_the_kernel_reaches_no_operating_system_interface_outside_its_threads_feature() {
    let mut problems = Vec::new();
    let mut gated = false;
    let mut clocks = 0;
    for package in READ {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join(format!("../{package}/src"));
        let mut files = Vec::new();
        sources(&root, &mut files);
        assert!(
            files.len() > 3,
            "the sources of {package} are read: {files:?}"
        );

        for file in &files {
            let relative = file.strip_prefix(&root).expect("under the root");
            if *package == "permguard-evaluator" && relative == Path::new(THREADS) {
                gated = true;
                continue;
            }
            let named = format!("{package}/src/{}", relative.display());
            let text = std::fs::read_to_string(file).expect("a source is read");
            // The tests of a module may wait, spawn and read: they are no part of a build.
            let code = text.split("#[cfg(test)]").next().unwrap_or_default();
            let code = code.split("#[cfg(all(test").next().unwrap_or_default();
            let code = uncommented(code);
            for module in native_modules(&code) {
                problems.push(format!("{named}: `std::{module}`"));
            }
            for name in NEVER_NAMED {
                if names(&code, name) {
                    problems.push(format!("{named}: `{name}`"));
                }
            }
            let reads = code.matches("Instant::now").count();
            let allowed = MONOTONIC
                .iter()
                .find(|(owner, path, _)| owner == package && relative == Path::new(path))
                .map_or(0, |(_, _, count)| *count);
            if reads != allowed {
                problems.push(format!(
                    "{named}: reads the monotonic clock {reads} times, where {allowed} is stated"
                ));
            }
            clocks += reads;
        }
    }
    assert!(gated, "the threads file is where it is expected: {THREADS}");
    assert!(
        problems.is_empty(),
        "the kernel or its contracts reach an operating system interface:\n  {}",
        problems.join("\n  ")
    );
    // The check reads real sources: the two reads it allows are there.
    assert_eq!(clocks, MONOTONIC.len(), "the monotonic clock's reads");

    // The file that starts a thread is compiled with the feature alone.
    let pool = Path::new(env!("CARGO_MANIFEST_DIR")).join("../permguard-evaluator/src/fanout.rs");
    let pool = std::fs::read_to_string(pool).expect("the pool");
    assert!(
        pool.contains("#[cfg(feature = \"threads\")]\nmod threads;"),
        "the threads file is compiled without its feature"
    );
}

/// The guard finds each form a path to a native module can take, and no sentence about one.
#[test]
fn test_the_guard_finds_a_native_module_however_it_is_written() {
    for reaching in [
        "let h = std::thread::spawn(|| ());",
        "use std::{fs, io};",
        "use std::{\n    io,\n    net::TcpStream,\n};",
        "use std :: process;",
    ] {
        assert!(
            !native_modules(&uncommented(reaching)).is_empty(),
            "{reaching}"
        );
    }
    for innocent in [
        "// a job never reaches std::thread here",
        "use std::sync::Arc;",
        "let threads = std::sync::Mutex::new(0);",
        "fn processed() {}",
    ] {
        assert!(
            native_modules(&uncommented(innocent)).is_empty(),
            "{innocent}"
        );
    }
    assert!(names("use std as core_std;", "std as"));
    assert!(names("tokio::spawn(x)", "tokio"));
    assert!(!names("let tokios = 1;", "tokio"));
}
