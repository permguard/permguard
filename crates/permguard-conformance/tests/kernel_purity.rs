// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The evaluator's kernel reaches no operating system interface
//! (`11-refactoring/1-dependencies.md`, The evaluator): no thread, file, socket, process,
//! environment or asynchronous runtime, outside the one file its `threads` feature compiles.
//!
//! What a build links is `dependency_direction.rs`'s to prove; this reads the sources, because a
//! standard library interface is in no dependency graph. It is what keeps a build for a target
//! with none of those interfaces, a browser one day, a matter of an engine and not of the kernel.
//! It claims no such target is supported: no engine is built for one here.

#![allow(clippy::expect_used)]

use std::path::{Path, PathBuf};

/// The interfaces the kernel does not reach.
const NATIVE: &[&str] = &[
    "std::thread",
    "std::fs",
    "std::net",
    "std::process",
    "std::env",
    "std::os",
    "tokio::",
];

/// The one file that starts a thread, compiled only with the `threads` feature.
const THREADS: &str = "fanout/threads.rs";

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
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../permguard-evaluator/src");
    let mut files = Vec::new();
    sources(&root, &mut files);
    assert!(files.len() > 3, "the kernel's sources are read: {files:?}");

    let mut problems = Vec::new();
    let mut gated = false;
    for file in &files {
        let relative = file.strip_prefix(&root).expect("under the root");
        if relative == Path::new(THREADS) {
            gated = true;
            continue;
        }
        let text = std::fs::read_to_string(file).expect("a source is read");
        // The tests of a module may wait, spawn and read: they are no part of a build.
        let code = text.split("#[cfg(test)]").next().unwrap_or_default();
        let code = code.split("#[cfg(all(test").next().unwrap_or_default();
        for (number, line) in code.lines().enumerate() {
            let line = line.trim_start();
            if line.starts_with("//") {
                continue;
            }
            for interface in NATIVE {
                if line.contains(interface) {
                    problems.push(format!(
                        "{}:{}: `{interface}`",
                        relative.display(),
                        number + 1
                    ));
                }
            }
        }
    }
    assert!(gated, "the threads file is where it is expected: {THREADS}");
    assert!(
        problems.is_empty(),
        "the kernel reaches an operating system interface:\n  {}",
        problems.join("\n  ")
    );

    // The file that starts a thread is compiled with the feature alone.
    let pool = std::fs::read_to_string(root.join("fanout.rs")).expect("the pool");
    assert!(
        pool.contains("#[cfg(feature = \"threads\")]\nmod threads;"),
        "the threads file is compiled without its feature"
    );
}
