// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The untrusted-boundary registry, and the check that keeps it equal to the code.
//!
//! `boundaries.json` beside this crate names every decoder that reads bytes or text from outside
//! the process — its crate, its entry point, the largest input it is asked to accept and what
//! enforces that, and the coverage-guided fuzz target that exercises it. A parser of trusted input
//! (operator configuration, bytes the process wrote itself) is listed under `trusted` with the
//! reason.
//!
//! The inventory is read from the source: every `pub fn` named `decode`, `decode_canonical`,
//! `parse`, `parse_strict` or `from_wire_parts` in a scanned crate, and every `pub fn` preceded by
//! the line `// conformance: boundary`. [`check`] fails when an inventory entry is not registered,
//! when a registered entry no longer exists, when a fuzz target is missing or does not call its
//! entry point, and when a bound is missing — so exporting, renaming or removing a decoder without
//! updating the registry fails CI.

use std::collections::BTreeSet;
use std::path::Path;

use serde::Deserialize;

/// The crates whose sources the inventory scans.
pub const SCANNED: &[&str] = &[
    "crates/permguard-core",
    "crates/permguard-objects",
    "crates/permguard-stream",
    "crates/permguard-decisions",
    "crates/permguard-events",
    "crates/permguard-notp",
    "crates/permguard-transport",
];

/// The function names that are decoders wherever they appear.
const DECODER_NAMES: &[&str] = &[
    "decode",
    "decode_canonical",
    "parse",
    "parse_strict",
    "from_wire_parts",
];

/// The comment that registers a decoder whose name is not one of [`DECODER_NAMES`].
pub const MARKER: &str = "// conformance: boundary";

/// The registry file.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Registry {
    /// Decoders of untrusted input.
    pub boundaries: Vec<Boundary>,
    /// Parsers of trusted input, kept out of the fuzz obligation with a reason.
    pub trusted: Vec<Trusted>,
}

/// One untrusted decoder.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Boundary {
    /// The owning crate.
    #[serde(rename = "crate")]
    pub owner: String,
    /// The file that defines it, relative to the repository root.
    pub source: String,
    /// `Type::function`, or `function` for a free function.
    pub item: String,
    /// The exported path a caller uses.
    pub entry: String,
    /// The largest input it is asked to accept, in bytes; also the fuzz `-max_len`.
    pub max_input_bytes: u64,
    /// What enforces that bound, or why none is enforced at the decoder yet.
    pub limit: String,
    /// The fuzz target that exercises it.
    pub fuzz: String,
}

/// One trusted parser.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Trusted {
    /// The file that defines it.
    pub source: String,
    /// `Type::function`, or `function`.
    pub item: String,
    /// Why its input is trusted.
    pub reason: String,
}

/// One decoder found in the source: its file and its `Type::function`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Found {
    pub source: String,
    pub item: String,
}

/// The decoders a source file exports, outside its top-level `#[cfg(test)]` module.
pub fn scan(source: &str, text: &str) -> Vec<Found> {
    let mut found = Vec::new();
    let mut current_impl: Option<String> = None;
    let mut in_tests = false;
    let mut marked = false;
    for line in text.lines() {
        if line.starts_with("#[cfg(test)]") {
            in_tests = true;
            continue;
        }
        if in_tests {
            if line.starts_with('}') {
                in_tests = false;
            }
            continue;
        }
        if line.starts_with("impl") {
            current_impl = impl_type(line);
        } else if line.starts_with('}') {
            current_impl = None;
        }
        let trimmed = line.trim_start();
        if trimmed == MARKER {
            marked = true;
            continue;
        }
        if let Some(rest) = trimmed.strip_prefix("pub fn ") {
            let name: String = rest
                .chars()
                .take_while(|c| c.is_alphanumeric() || *c == '_')
                .collect();
            if marked || DECODER_NAMES.contains(&name.as_str()) {
                let indented = line.starts_with(' ');
                let item = match (&current_impl, indented) {
                    (Some(owner), true) => format!("{owner}::{name}"),
                    _ => name,
                };
                found.push(Found {
                    source: source.to_owned(),
                    item,
                });
            }
        }
        // A marker binds the next function only; doc comments and attributes may sit between.
        if !trimmed.starts_with("///") && !trimmed.starts_with("#[") && !trimmed.is_empty() {
            marked = false;
        }
    }

    found
}

/// The type an `impl` line implements for: `impl X {`, `impl<T> X<T> {` or `impl Trait for X {`.
fn impl_type(line: &str) -> Option<String> {
    let mut rest = line.strip_prefix("impl")?;
    if rest.starts_with('<') {
        let mut depth = 0usize;
        let end = rest.char_indices().find_map(|(index, c)| {
            match c {
                '<' => depth += 1,
                '>' => {
                    depth -= 1;
                    if depth == 0 {
                        return Some(index + 1);
                    }
                }
                _ => {}
            }
            None
        })?;
        rest = &rest[end..];
    }
    let rest = rest.trim_start();
    let rest = rest.split_once(" for ").map_or(rest, |(_, target)| target);
    let name: String = rest
        .trim_start()
        .chars()
        .take_while(|c| c.is_alphanumeric() || *c == '_')
        .collect();
    (!name.is_empty()).then_some(name)
}

/// The fuzz targets `fuzz/Cargo.toml` declares, as `(name, path)`.
pub fn fuzz_targets(manifest: &str) -> Vec<(String, String)> {
    let mut targets = Vec::new();
    let mut name = None;
    for line in manifest.lines() {
        let line = line.trim();
        if line == "[[bin]]" {
            name = None;
        } else if let Some(value) = line.strip_prefix("name = ") {
            name = Some(value.trim_matches('"').to_owned());
        } else if let Some(value) = line.strip_prefix("path = ")
            && let Some(name) = name.take()
        {
            targets.push((name, value.trim_matches('"').to_owned()));
        }
    }

    targets
}

/// Every reason the registry and the code disagree; empty when they agree.
///
/// `read` answers a file's text by its path relative to the repository root, so the check can run
/// over the real tree or over a fixture.
pub fn check(
    registry: &Registry,
    inventory: &[Found],
    fuzz_manifest: &str,
    read: impl Fn(&str) -> Option<String>,
) -> Vec<String> {
    let mut problems = Vec::new();
    let registered: BTreeSet<Found> = registry
        .boundaries
        .iter()
        .map(|boundary| Found {
            source: boundary.source.clone(),
            item: boundary.item.clone(),
        })
        .chain(registry.trusted.iter().map(|trusted| Found {
            source: trusted.source.clone(),
            item: trusted.item.clone(),
        }))
        .collect();
    let exported: BTreeSet<Found> = inventory.iter().cloned().collect();

    for missing in exported.difference(&registered) {
        problems.push(format!(
            "`{}` in {} decodes outside input and is not in boundaries.json",
            missing.item, missing.source
        ));
    }
    for dangling in registered.difference(&exported) {
        problems.push(format!(
            "boundaries.json names `{}` in {}, which the source no longer exports",
            dangling.item, dangling.source
        ));
    }
    let listed = registry.boundaries.len() + registry.trusted.len();
    if listed != registered.len() {
        problems.push("boundaries.json lists one decoder twice".to_owned());
    }

    let targets = fuzz_targets(fuzz_manifest);
    for (name, path) in &targets {
        if read(&format!("fuzz/{path}")).is_none() {
            problems.push(format!(
                "the fuzz target `{name}` names {path}, which does not exist"
            ));
        }
    }
    for boundary in &registry.boundaries {
        if boundary.max_input_bytes == 0 || boundary.limit.trim().is_empty() {
            problems.push(format!("`{}` has no bound", boundary.item));
        }
        if boundary.owner.is_empty()
            || !boundary
                .source
                .starts_with(&format!("crates/{}/", boundary.owner))
        {
            problems.push(format!(
                "`{}` names the crate `{}`, which does not own {}",
                boundary.item, boundary.owner, boundary.source
            ));
        }
        let Some((_, path)) = targets.iter().find(|(name, _)| *name == boundary.fuzz) else {
            problems.push(format!(
                "`{}` names the fuzz target `{}`, which fuzz/Cargo.toml does not declare",
                boundary.item, boundary.fuzz
            ));
            continue;
        };
        let called = boundary
            .entry
            .rsplit("::")
            .take(2)
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .collect::<Vec<_>>()
            .join("::");
        if !read(&format!("fuzz/{path}")).is_some_and(|text| text.contains(&called)) {
            problems.push(format!(
                "the fuzz target `{}` does not call `{called}`",
                boundary.fuzz
            ));
        }
    }

    problems
}

/// Reads every scanned crate under `root` into an inventory.
pub fn inventory(root: &Path) -> Vec<Found> {
    let mut found = Vec::new();
    for owner in SCANNED {
        walk(root, &root.join(owner).join("src"), &mut found);
    }
    found.sort();
    found
}

fn walk(root: &Path, directory: &Path, found: &mut Vec<Found>) {
    let Ok(entries) = std::fs::read_dir(directory) else {
        return;
    };
    let mut paths: Vec<_> = entries
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .collect();
    paths.sort();
    for path in paths {
        if path.is_dir() {
            walk(root, &path, found);
        } else if path.extension().is_some_and(|extension| extension == "rs")
            && let Ok(text) = std::fs::read_to_string(&path)
        {
            let source = path
                .strip_prefix(root)
                .unwrap_or(&path)
                .to_string_lossy()
                .replace('\\', "/");
            found.extend(scan(&source, &text));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SOURCE: &str = r#"
pub fn decode(bytes: &[u8]) -> Result<Object, Error> {}

impl SignedHead {
    /// Reads one.
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {}
    pub fn encode(&self) -> Vec<u8> {}
}

impl<T> fmt::Display for Wrapper<T> {
    fn parse() {}
}

impl Cursor {
    /// Reads a token.
    // conformance: boundary
    pub fn open(token: &str) -> Result<Self, Error> {}
    pub fn seal(&self) -> String {}
}

#[cfg(test)]
mod tests {
    pub fn decode() {}
}
"#;

    fn found(item: &str) -> Found {
        Found {
            source: "crates/permguard-objects/src/x.rs".to_owned(),
            item: item.to_owned(),
        }
    }

    #[test]
    fn test_the_scan_finds_named_and_marked_decoders_and_nothing_in_tests() {
        assert_eq!(
            scan("crates/permguard-objects/src/x.rs", SOURCE),
            vec![
                found("decode"),
                found("SignedHead::decode"),
                found("Cursor::open")
            ]
        );
        assert_eq!(
            impl_type("impl<T: Clone> Trait<T> for Holder<T> {"),
            Some("Holder".into())
        );
    }

    fn registry(items: &[&str], fuzz: &str) -> Registry {
        Registry {
            boundaries: items
                .iter()
                .map(|item| Boundary {
                    owner: "permguard-objects".to_owned(),
                    source: "crates/permguard-objects/src/x.rs".to_owned(),
                    item: (*item).to_owned(),
                    entry: format!("permguard_objects::x::{item}"),
                    max_input_bytes: 1024,
                    limit: "the test".to_owned(),
                    fuzz: fuzz.to_owned(),
                })
                .collect(),
            trusted: Vec::new(),
        }
    }

    const MANIFEST: &str = "[[bin]]\nname = \"x\"\npath = \"fuzz_targets/x.rs\"\n";

    fn read(path: &str) -> Option<String> {
        (path == "fuzz/fuzz_targets/x.rs")
            .then(|| "x::decode(data); SignedHead::decode(data); Cursor::open(t)".to_owned())
    }

    #[test]
    fn test_a_registry_equal_to_the_code_passes() {
        let inventory = scan("crates/permguard-objects/src/x.rs", SOURCE);
        let registry = registry(&["decode", "SignedHead::decode", "Cursor::open"], "x");

        assert_eq!(
            check(&registry, &inventory, MANIFEST, read),
            Vec::<String>::new()
        );
    }

    #[test]
    fn test_an_unregistered_export_and_a_dangling_entry_both_fail() {
        let inventory = scan("crates/permguard-objects/src/x.rs", SOURCE);
        let registry = registry(&["decode", "SignedHead::decode", "Gone::decode"], "x");
        let problems = check(&registry, &inventory, MANIFEST, read);

        assert!(
            problems
                .iter()
                .any(|p| p.contains("`Cursor::open`") && p.contains("not in boundaries.json")),
            "{problems:?}"
        );
        assert!(
            problems
                .iter()
                .any(|p| p.contains("`Gone::decode`") && p.contains("no longer exports")),
            "{problems:?}"
        );
    }

    #[test]
    fn test_a_missing_target_an_uncalled_entry_and_a_missing_bound_fail() {
        let inventory = vec![found("decode")];
        let mut unknown_target = registry(&["decode"], "y");
        unknown_target.boundaries[0].fuzz = "y".to_owned();
        assert!(
            check(&unknown_target, &inventory, MANIFEST, read)
                .iter()
                .any(|p| p.contains("does not declare"))
        );

        let mut uncalled = registry(&["decode"], "x");
        uncalled.boundaries[0].entry = "permguard_objects::other::decode".to_owned();
        assert!(
            check(&uncalled, &inventory, MANIFEST, read)
                .iter()
                .any(|p| p.contains("does not call `other::decode`"))
        );

        let mut unbounded = registry(&["decode"], "x");
        unbounded.boundaries[0].max_input_bytes = 0;
        assert!(
            check(&unbounded, &inventory, MANIFEST, read)
                .iter()
                .any(|p| p.contains("has no bound"))
        );

        let missing_file = "[[bin]]\nname = \"x\"\npath = \"fuzz_targets/gone.rs\"\n";
        assert!(
            check(&registry(&["decode"], "x"), &inventory, missing_file, read)
                .iter()
                .any(|p| p.contains("does not exist"))
        );
    }
}
