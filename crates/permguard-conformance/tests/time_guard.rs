// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The Host's time paths read its time guard (WP-2.12), enforced on the source.
//!
//! | Path                                    | Reads                                      |
//! | --------------------------------------- | ------------------------------------------ |
//! | identity: `permguard-host/src/authz/`   | the guard: token expiry, key-set staleness |
//! | the Host API: `permguard-host/src/api/` | the guard: grant expiry, the replay window |
//! | signing: `composition.rs`               | the guard: time-sensitive artifacts        |
//! | `signed_at`: the NOTP engine            | the signing ring's time, the guard's       |
//! | keys: the server's key rings            | the guard, through `GuardedKeyClock`       |
//!
//! Memberships and streams are not at the Host yet; their paths join this list with their
//! packages. A path here may not read the operating system's wall clock: not directly, not
//! through the system `Clock`, and not through a guard of its own, except where [`ALLOWED`] says
//! how many lines may and why. The server may not build a key ring on the system clock. `Instant`
//! stays allowed: monotonic time is what a duration is measured in, and it cannot step back.

#![allow(clippy::expect_used)]

use std::path::{Path, PathBuf};

/// Wall-clock reads the guarded paths may not make: the operating system's clock directly, the
/// system `Clock`, and a guard of its own on the system clocks.
const CLOCK_READS: &[&str] = &[
    "SystemTime::now",
    "Utc::now",
    "Local::now",
    "now_utc",
    "SystemClock",
    "TimeGuard::system(",
];

/// Key rings built on the system clock: `DirectoryKeyManager::new` and `with_algorithm` read
/// `SystemClock` behind the caller's back.
const UNGUARDED_RINGS: &[&str] = &[
    "DirectoryKeyManager::new(",
    "DirectoryKeyManager::with_algorithm(",
];

/// The reads allowed anyway: the file, how many lines may read, and why.
const ALLOWED: &[(&str, usize, &str)] = &[
    (
        "permguard-server/src/app.rs",
        2,
        "the guard's own wall source, `SystemClock`, handed to `TimeGuard::open`; and the seed of \
         `permguard verify --sample`, which picks the files an offline check reads and is compared \
         with nothing",
    ),
    (
        "permguard-host/src/authz/store.rs",
        1,
        "`store::now`, for the offline `permguard host grants` and for nothing a running Host reads",
    ),
    (
        "permguard-host/src/authz/mod.rs",
        2,
        "the default guard of `Authorization::new` and `public_only`, which a server replaces with \
         `with_time`",
    ),
    (
        "permguard-host/src/authz/mapper.rs",
        1,
        "the default guard of `PrincipalMapper::new`; a server builds it with `with_time`",
    ),
    (
        "permguard-host/src/api/replay.rs",
        1,
        "the default guard of `Replay::open`, which a server replaces with `with_time`",
    ),
    (
        "permguard-host/src/composition.rs",
        1,
        "the default guard of a `Host` built without one; a server hands its own with `time`",
    ),
];

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn rust_files(path: &Path, into: &mut Vec<PathBuf>) {
    if path.is_file() {
        if path.extension().is_some_and(|extension| extension == "rs") {
            into.push(path.to_path_buf());
        }
        return;
    }
    for entry in std::fs::read_dir(path).expect("a source directory") {
        rust_files(&entry.expect("an entry").path(), into);
    }
}

/// The file without its test-only modules: each `#[cfg(test)]` followed by a `mod` item is cut
/// out to its matching closing brace. A heuristic over text, not a parser: braces inside strings
/// in a test module could fool it, which would only scan more.
fn production(path: &Path) -> String {
    let source = std::fs::read_to_string(path).expect("a source file");
    let mut kept = String::new();
    let mut rest = source.as_str();
    while let Some(at) = rest.find("#[cfg(test)]") {
        let after = &rest[at + "#[cfg(test)]".len()..];
        let item = after.trim_start();
        let is_module = ["mod ", "pub mod ", "pub(crate) mod "]
            .iter()
            .any(|start| item.starts_with(start));
        let Some(open) = after.find('{').filter(|_| is_module) else {
            kept.push_str(&rest[..at + "#[cfg(test)]".len()]);
            rest = after;
            continue;
        };
        kept.push_str(&rest[..at]);
        let mut depth = 0usize;
        let mut end = after.len();
        for (index, character) in after[open..].char_indices() {
            match character {
                '{' => depth += 1,
                '}' => {
                    depth -= 1;
                    if depth == 0 {
                        end = open + index + 1;
                        break;
                    }
                }
                _ => {}
            }
        }
        // Keep the line count, so a reported line number is still the file's.
        kept.extend(std::iter::repeat_n(
            '\n',
            after[..end].matches('\n').count(),
        ));
        rest = &after[end..];
    }
    kept.push_str(rest);
    kept
}

/// How many lines of `file` may read anyway.
fn allowed(file: &Path) -> usize {
    let file = file.to_string_lossy().replace('\\', "/");
    ALLOWED
        .iter()
        .find(|(path, _, _)| file.ends_with(path))
        .map_or(0, |(_, lines, _)| *lines)
}

fn offending(path: &Path, needles: &[&str]) -> Vec<String> {
    production(path)
        .lines()
        .enumerate()
        .filter(|(_, line)| !line.trim_start().starts_with("//"))
        .filter(|(_, line)| needles.iter().any(|needle| line.contains(needle)))
        .map(|(number, line)| format!("{}:{}: {}", path.display(), number + 1, line.trim()))
        .collect()
}

#[test]
fn the_hosts_time_paths_read_the_time_guard() {
    let host = root().join("crates/permguard-host/src");
    let mut files = Vec::new();
    for path in ["authz", "api", "composition.rs"] {
        rust_files(&host.join(path), &mut files);
    }
    // The head statement's `signed_at` is stamped where the NOTP engine builds it.
    let control = root().join("crates/permguard-control-plane/src");
    for path in ["engine.rs", "notp"] {
        rust_files(&control.join(path), &mut files);
    }
    assert!(files.len() > 5, "the scan found the Host's sources");
    let mut found = Vec::new();
    for file in &files {
        let reads = offending(file, CLOCK_READS);
        if reads.len() > allowed(file) {
            found.extend(reads);
        }
    }
    assert!(
        found.is_empty(),
        "a Host time path reads the system clock instead of the guard:\n{}",
        found.join("\n")
    );
}

#[test]
fn the_server_reads_no_clock_of_its_own_and_builds_no_ring_on_one() {
    let server = root().join("crates/permguard-server/src");
    let mut files = Vec::new();
    rust_files(&server, &mut files);
    let mut found = Vec::new();
    for file in &files {
        found.extend(offending(file, UNGUARDED_RINGS));
        let reads = offending(file, CLOCK_READS);
        if reads.len() > allowed(file) {
            found.extend(reads);
        }
    }
    assert!(
        found.is_empty(),
        "the server reads the system clock, or builds a ring on it, outside the guard:\n{}",
        found.join("\n")
    );
}
