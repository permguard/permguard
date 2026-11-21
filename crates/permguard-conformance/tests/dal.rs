// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! One way to durable state (iteration 03, WP-25.2): the inventory of `permguard_conformance::dal`
//! finds no source that reaches the filesystem or the storage library itself outside the lists
//! of `dal.json`, no list entry the code no longer needs, and a seeded reach however it is
//! written.

#![allow(clippy::expect_used)]

use std::path::Path;

use permguard_conformance::dal::{
    Backend, Configured, Direct, Reach, Rules, check, is_backend, judge, rules, scan,
};

fn root() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

#[test]
fn test_no_source_reaches_storage_outside_the_lists() {
    let root = root();
    let rules = rules(&root).expect("the rules read");
    let violations = check(&root, &rules);
    assert!(
        violations.is_empty(),
        "sources that reach the filesystem or the storage library themselves, or stale entries of \
         dal.json; go through a store contract, or list the file with the package that moves it:\n{}",
        violations
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join("\n")
    );
}

/// The scope names crates that exist, so a renamed crate cannot leave the check reading nothing.
#[test]
fn test_every_scoped_crate_exists_and_the_library_is_a_backend() {
    let root = root();
    let rules = rules(&root).expect("the rules read");
    assert!(!rules.scope.is_empty(), "the scope is empty");
    for name in &rules.scope {
        assert!(
            root.join("crates").join(name).join("src").is_dir(),
            "the scope names `{name}`, which is not a crate of this repository"
        );
    }
    assert!(
        is_backend(
            "crates/permguard-host/src/storage/journal.rs",
            &rules.backends
        ),
        "the storage library is not listed as a backend"
    );
}

fn whats(found: &[Reach]) -> Vec<(&str, &str)> {
    found
        .iter()
        .map(|reach| (reach.what.as_str(), reach.detail.as_str()))
        .collect()
}

/// A renamed import, a glob, a path written in full and a path inside a macro are all found.
#[test]
fn test_a_seeded_reach_is_found_however_it_is_written() {
    let seeded = r#"
        use std::fs as files;
        use std::{fs::File, io};
        use tokio::fs::*;
        use permguard_host::storage::{Dir, write};

        pub fn read(path: &std::path::Path) -> io::Result<Vec<u8>> {
            std::fs::read(path)
        }

        pub fn told(path: &std::path::Path) -> String {
            format!("{:?}", std::fs::metadata(path).map(|m| m.len()))
        }

        pub fn kept(dir: &permguard_host::storage::Dir) {}

        #[cfg(not(test))]
        pub fn production_only(path: &str) -> io::Result<String> {
            std::fs::read_to_string(path)
        }

        #[cfg(test)]
        mod tests {
            pub fn damage(path: &str) { std::fs::remove_file(path).unwrap(); }
        }

        #[cfg(all(test, unix))]
        pub fn unix_test_only(path: &str) { std::fs::remove_file(path).unwrap(); }
    "#;
    let found = scan("crates/seeded/src/lib.rs", "seeded", seeded);
    assert_eq!(
        whats(&found),
        vec![
            ("filesystem", "std::fs"),
            ("filesystem", "std::fs::File"),
            ("filesystem", "tokio::fs"),
            ("storage library", "permguard_host::storage::Dir"),
            ("storage library", "permguard_host::storage::write"),
            ("filesystem", "std::fs::read"),
            ("filesystem", "std::fs::metadata"),
            ("storage library", "permguard_host::storage::Dir"),
            ("filesystem", "std::fs::read_to_string"),
        ],
        "{found:#?}"
    );
}

/// Inside the crate that holds the storage library, its own `storage` module is the library,
/// however the path reaches it; in any other crate a module of that name is not.
#[test]
fn test_the_library_is_found_by_its_local_path_only_in_its_own_crate() {
    let local = r"
        use crate::storage::write::Published;
        use super::storage::Dir;

        pub fn open() -> crate::storage::journal::Options {
            self::storage::journal::Options::default()
        }

        pub fn other() -> crate::health::Storage {
            crate::health::storage()
        }
    ";
    let inside = scan(
        "crates/permguard-host/src/seeded.rs",
        "permguard-host",
        local,
    );
    assert_eq!(
        whats(&inside),
        vec![
            ("storage library", "crate::storage::write::Published"),
            ("storage library", "super::storage::Dir"),
            ("storage library", "crate::storage::journal::Options"),
            (
                "storage library",
                "self::storage::journal::Options::default"
            ),
        ],
        "{inside:#?}"
    );
    let outside = scan("crates/other/src/seeded.rs", "other", local);
    assert!(outside.is_empty(), "{outside:#?}");
}

/// A file the parser does not read is a finding, never a file the check skipped.
#[test]
fn test_a_file_that_does_not_parse_is_reported() {
    let found = scan("crates/seeded/src/lib.rs", "seeded", "pub fn broken( {");
    assert_eq!(found.len(), 1, "{found:#?}");
    assert_eq!(found[0].what, "unparsed");
}

fn reach(source: &str) -> Reach {
    Reach {
        source: source.to_owned(),
        line: 7,
        what: "filesystem".to_owned(),
        detail: "std::fs::read".to_owned(),
    }
}

fn seeded_rules() -> Rules {
    Rules {
        scope: vec!["seeded".to_owned()],
        backends: vec![Backend {
            path: "crates/seeded/src/backend/".to_owned(),
            reason: "the seeded backend".to_owned(),
        }],
        configured: vec![Configured {
            source: "crates/seeded/src/given.rs".to_owned(),
            reason: "reads what the configuration names".to_owned(),
        }],
        direct: vec![Direct {
            source: "crates/seeded/src/listed.rs".to_owned(),
            until: "WP-26.1".to_owned(),
        }],
    }
}

/// What the lists cover passes, a file outside them fails, and so does an entry nothing needs.
#[test]
fn test_the_lists_cover_exactly_what_they_name() {
    let everything = |_: &str| true;
    let covered = [
        reach("crates/seeded/src/listed.rs"),
        reach("crates/seeded/src/given.rs"),
    ];
    assert!(
        judge(&covered, &seeded_rules(), &everything).is_empty(),
        "what the lists name is refused"
    );

    let mut new = covered.to_vec();
    new.push(reach("crates/seeded/src/new.rs"));
    let refused = judge(&new, &seeded_rules(), &everything);
    assert_eq!(refused.len(), 1, "{refused:#?}");
    assert_eq!(refused[0].source, "crates/seeded/src/new.rs");
    assert_eq!(refused[0].line, 7);

    // The file was moved behind its contract and its entry was left: the list must shrink.
    let moved = [reach("crates/seeded/src/given.rs")];
    let stale = judge(&moved, &seeded_rules(), &everything);
    assert_eq!(stale.len(), 1, "{stale:#?}");
    assert_eq!(stale[0].source, "crates/seeded/src/listed.rs");
    assert!(stale[0].detail.contains("no longer reaches storage"));

    let unneeded = [reach("crates/seeded/src/listed.rs")];
    let stale = judge(&unneeded, &seeded_rules(), &everything);
    assert_eq!(stale.len(), 1, "{stale:#?}");
    assert_eq!(stale[0].source, "crates/seeded/src/given.rs");
}

/// An entry is refused when it names no package, is listed twice, or names a backend that is
/// not there.
#[test]
fn test_a_malformed_entry_is_refused() {
    let everything = |_: &str| true;
    let covered = [
        reach("crates/seeded/src/listed.rs"),
        reach("crates/seeded/src/given.rs"),
    ];

    let mut rules = seeded_rules();
    rules.direct[0].until = "later".to_owned();
    let refused = judge(&covered, &rules, &everything);
    assert_eq!(refused.len(), 1, "{refused:#?}");
    assert!(refused[0].detail.contains("`until` is not a package"));

    let mut rules = seeded_rules();
    rules.direct.push(rules.direct[0].clone());
    let refused = judge(&covered, &rules, &everything);
    assert_eq!(refused.len(), 1, "{refused:#?}");
    assert!(refused[0].detail.contains("listed twice"));

    let mut rules = seeded_rules();
    rules.configured[0].reason = "  ".to_owned();
    let refused = judge(&covered, &rules, &everything);
    assert_eq!(refused.len(), 1, "{refused:#?}");
    assert!(refused[0].detail.contains("without a reason"));

    let nothing = |_: &str| false;
    let refused = judge(&covered, &seeded_rules(), &nothing);
    assert_eq!(refused.len(), 1, "{refused:#?}");
    assert_eq!(refused[0].source, "crates/seeded/src/backend/");
    assert!(refused[0].detail.contains("not in the repository"));
}

/// A backend is a directory and everything below it, or one file and nothing else.
#[test]
fn test_a_backend_is_a_directory_or_one_file() {
    let backends = [
        Backend {
            path: "crates/seeded/src/backend/".to_owned(),
            reason: "a directory".to_owned(),
        },
        Backend {
            path: "crates/seeded/src/files.rs".to_owned(),
            reason: "a file".to_owned(),
        },
    ];
    assert!(is_backend("crates/seeded/src/backend/deep/a.rs", &backends));
    assert!(is_backend("crates/seeded/src/files.rs", &backends));
    assert!(!is_backend("crates/seeded/src/files.rs.bak", &backends));
    assert!(!is_backend("crates/seeded/src/backend.rs", &backends));
}
