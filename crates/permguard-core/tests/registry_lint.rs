// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The two registries are the only place a domain string or a stable code may be spelled.
//!
//! A domain string is part of what a signature means and a code is what a client branches on, so
//! both are contracts, and a contract spelled twice is two chances to drift. These tests walk every
//! crate's non-test sources and fail on a literal that the registries do not own.
//!
//! Test code is skipped on purpose: a test that pins the exact bytes of a wire format *should*
//! spell them, so that a change to a registry constant fails a test somewhere.

use std::fs;
use std::path::{Path, PathBuf};

use permguard_core::{codes, domains};

/// Every `.rs` file under `crates/*/src`, except the registries themselves.
fn sources() -> Vec<PathBuf> {
    let crates = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_default();
    let mut files = Vec::new();
    collect(&crates, &mut files);
    files.sort();
    files
        .into_iter()
        .filter(|path| {
            let text = path.to_string_lossy();
            text.contains("/src/")
                && !text.contains("/tests/")
                && !text.ends_with("permguard-core/src/domains.rs")
                && !text.ends_with("permguard-core/src/codes.rs")
        })
        .collect()
}

fn collect(directory: &Path, into: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(directory) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            if path.file_name().is_some_and(|name| name == "target") {
                continue;
            }
            collect(&path, into);
        } else if path.extension().is_some_and(|extension| extension == "rs") {
            into.push(path);
        }
    }
}

/// The lines of a file that are code rather than test code or comments.
///
/// A top-level `#[cfg(test)]` module runs to the end of the file in every crate here, so scanning
/// stops at that attribute. Comment lines are skipped because documentation quotes the strings.
fn code_lines(path: &Path) -> Vec<(usize, String)> {
    let Ok(text) = fs::read_to_string(path) else {
        return Vec::new();
    };
    let mut lines = Vec::new();
    for (index, line) in text.lines().enumerate() {
        let trimmed = line.trim_start();
        if trimmed.starts_with("#[cfg(test)]") {
            break;
        }
        if trimmed.starts_with("//") {
            continue;
        }
        lines.push((index + 1, line.to_owned()));
    }
    lines
}

/// Every double-quoted literal on a line, without the quotes, with `\n` escapes decoded.
fn literals(line: &str) -> Vec<String> {
    let mut found = Vec::new();
    let mut rest = line;
    while let Some(start) = rest.find('"') {
        let after = &rest[start + 1..];
        let Some(end) = after.find('"') else {
            break;
        };
        found.push(after[..end].replace("\\n", "\n"));
        rest = &after[end + 1..];
    }
    found
}

fn looks_like_domain(literal: &str) -> bool {
    literal.starts_with("permguard.")
        || literal.starts_with("application/vnd.permguard")
        || literal.starts_with("urn:permguard:")
}

#[test]
fn test_no_domain_literal_is_spelled_outside_the_registry() {
    let registered: Vec<&str> = domains::all().into_iter().map(|(_, value)| value).collect();
    let mut offences = Vec::new();

    for path in sources() {
        for (number, line) in code_lines(&path) {
            // Generated protobuf packages are named by the build script, not by this registry.
            if line.contains("include_proto!") {
                continue;
            }
            for literal in literals(&line) {
                if looks_like_domain(&literal) {
                    let known = if registered.contains(&literal.as_str()) {
                        "registered"
                    } else {
                        "unregistered"
                    };
                    offences.push(format!(
                        "{}:{number}: {literal:?} ({known})",
                        path.display()
                    ));
                }
            }
        }
    }

    assert!(
        offences.is_empty(),
        "domain strings spelled outside `permguard_core::domains` (use the constant):\n{}",
        offences.join("\n")
    );
}

/// The call shapes through which a stable code enters the program.
const CODE_SHAPES: [&str; 6] = [
    "ApiError::new(",
    "malformed(",
    "Refusal::new(",
    "Malformed::new(",
    "code: \"",
    "refusal(",
];

#[test]
fn test_every_stable_code_is_registered() {
    let registered: Vec<&str> = codes::all().into_iter().map(|(_, value)| value).collect();
    let classes = [
        "validation",
        "conflict",
        "not_found",
        "unavailable",
        "internal",
    ];
    let mut offences = Vec::new();

    for path in sources() {
        let lines = code_lines(&path);
        for (position, (number, line)) in lines.iter().enumerate() {
            let shaped = CODE_SHAPES.iter().any(|shape| line.contains(shape))
                || lines
                    .get(position.wrapping_sub(1))
                    .is_some_and(|(_, previous)| {
                        CODE_SHAPES
                            .iter()
                            .any(|shape| previous.trim_end().ends_with(shape.trim_end_matches('"')))
                    });
            if !shaped {
                continue;
            }
            for literal in literals(line) {
                let snake = !literal.is_empty()
                    && literal
                        .chars()
                        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
                    && literal.contains('_');
                if snake
                    && !classes.contains(&literal.as_str())
                    && !registered.contains(&literal.as_str())
                {
                    offences.push(format!("{}:{number}: {literal:?}", path.display()));
                }
            }
        }
    }

    assert!(
        offences.is_empty(),
        "stable codes spelled outside `permguard_core::codes`:\n{}",
        offences.join("\n")
    );
}
