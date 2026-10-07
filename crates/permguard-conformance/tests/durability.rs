// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! One durability implementation (WP-1.11): the inventory of `permguard_conformance::durability`
//! finds no primitive outside the storage library and the allow-list, and a seeded violation is
//! found whatever it is called.

#![allow(clippy::expect_used)]

use std::path::Path;

use permguard_conformance::durability::{Allowed, Allowlist, allowlist, check, judge, scan};

fn root() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

#[test]
fn test_no_durability_primitive_lives_outside_the_storage_library() {
    let root = root();
    let allowlist = allowlist(&root).expect("the allow-list reads");
    let violations = check(&root, &allowlist);
    assert!(
        violations.is_empty(),
        "durability primitives outside permguard-host::storage, or stale allow-list entries; \
         route them through the library or list them in durability.json with a reason:\n{}",
        violations
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join("\n")
    );
}

/// A renamed import, a wrapper and a glob are all seen as the primitive they are.
#[test]
fn test_a_seeded_violation_is_found_however_it_is_named() {
    let seeded = r#"
        use std::fs::rename as publish;
        use std::fs::{hard_link as pin, copy};
        use std::fs as filesystem;
        mod wrapped { pub use std::fs::*; }

        pub fn finish(a: &str, b: &str) -> std::io::Result<()> {
            publish(a, b)?;
            pin(a, b)?;
            copy(a, b)?;
            std::fs::rename(a, b)
        }

        pub fn flush(file: &std::fs::File) -> std::io::Result<()> {
            file.sync_data()?;
            file.set_len(0)?;
            file.sync_all()
        }

        pub fn staged(path: &std::path::Path) -> std::path::PathBuf {
            path.with_extension("json.tmp")
        }

        pub fn aliased(a: &str, b: &str, file: &std::fs::File) -> std::io::Result<()> {
            filesystem::rename(a, b)?;
            let pointer = std::fs::hard_link;
            pointer(a, b)?;
            std::fs::File::sync_all(file)?;
            std::fs::write(a, b)?;
            let name = format!("{a}.tmp");
            tracing::info!(temporary = %name, "staged");
            Ok(())
        }

        #[cfg(not(test))]
        pub fn production_only(a: &str, b: &str) -> std::io::Result<()> {
            std::fs::rename(a, b)
        }

        #[cfg(test)]
        mod tests {
            pub fn damage(file: &std::fs::File) { file.set_len(3).unwrap(); }
        }

        #[cfg(all(test, unix))]
        pub fn unix_test_only(file: &std::fs::File) { file.set_len(3).unwrap(); }
    "#;
    let found = scan("crates/seeded/src/lib.rs", seeded);
    let primitives: Vec<(&str, &str)> = found
        .iter()
        .map(|v| (v.item.as_str(), v.primitive.as_str()))
        .collect();
    assert_eq!(
        primitives,
        vec![
            ("finish", "rename"),
            ("finish", "hard_link"),
            ("finish", "copy"),
            ("finish", "rename"),
            ("flush", "flush"),
            ("flush", "truncate"),
            ("flush", "flush"),
            ("staged", "temporary"),
            ("aliased", "rename"),
            ("aliased", "hard_link"),
            ("aliased", "flush"),
            ("aliased", "write"),
            ("aliased", "temporary"),
            ("production_only", "rename"),
        ],
        "{found:#?}"
    );
    // The allow-list covers exactly what it names, and a stale entry is itself reported.
    let judged = judge(
        found.clone(),
        &Allowlist {
            allowed: vec![
                Allowed {
                    source: "crates/seeded/src/lib.rs".to_owned(),
                    item: "finish".to_owned(),
                    primitive: "copy".to_owned(),
                    reason: "a test".to_owned(),
                },
                Allowed {
                    source: "crates/seeded/src/lib.rs".to_owned(),
                    item: "nothing".to_owned(),
                    primitive: "rename".to_owned(),
                    reason: "stale".to_owned(),
                },
            ],
        },
    );
    assert_eq!(judged.len(), found.len() - 1 + 1, "{judged:#?}");
    assert!(judged.iter().any(|v| v.item == "nothing" && v.line == 0));
    assert!(!judged.iter().any(|v| v.primitive == "copy"));
}

/// A file the parser does not read is reported, never skipped.
#[test]
fn test_a_file_that_does_not_parse_is_a_violation_of_its_own() {
    let found = scan("crates/seeded/src/broken.rs", "pub fn f( {");
    assert_eq!(found.len(), 1, "{found:#?}");
    assert_eq!(found[0].primitive, "unparsed");
}
