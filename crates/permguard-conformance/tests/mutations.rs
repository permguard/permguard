// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The mutation engine is the only writer of security state (WP-3.6): the inventory of
//! `permguard_conformance::mutations` finds no direct mutation, and a seeded bypass is found
//! whatever it is called.

#![allow(clippy::expect_used)]

use std::path::Path;

use permguard_conformance::mutations::{Exempt, Guarded, Rules, check, rules, scan};

fn root() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

const ENGINE: &str = "crates/permguard-host/src/operations/mutation.rs";
const STORE: &str = "crates/permguard-host/src/authz/store.rs";

fn seeded_rules() -> Rules {
    Rules {
        engine: ENGINE.to_owned(),
        token: "Applying".to_owned(),
        guarded: vec![Guarded {
            source: STORE.to_owned(),
            calls: vec!["append".to_owned()],
            fields: vec!["journal".to_owned()],
            exempt: vec![Exempt {
                item: "history".to_owned(),
                reason: "reads".to_owned(),
            }],
            state: "the grant journal".to_owned(),
        }],
    }
}

fn rules_of(found: &[permguard_conformance::durability::Violation]) -> Vec<(String, String)> {
    found
        .iter()
        .map(|violation| (violation.item.clone(), violation.primitive.clone()))
        .collect()
}

#[test]
fn test_no_security_state_is_written_outside_the_mutation_engine() {
    let root = root();
    let rules = rules(&root).expect("the rules read");
    let violations = check(&root, &rules);
    assert!(
        violations.is_empty(),
        "security state written outside the mutation engine, or a stale rule in \
         mutations.json; take the engine's token in the function that writes:\n{}",
        violations
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join("\n")
    );
}

/// A wrapper, a renamed call and a method named as a value write the journal all the same.
#[test]
fn test_a_seeded_write_without_the_token_is_found_however_it_is_wrapped() {
    let seeded = r#"
        impl GrantStore {
            pub fn issue(&self, applying: &Applying<'_>, record: &[u8]) {
                self.journal.lock().append(1, record);
            }

            fn sneaky(&self, record: &[u8]) {
                self.journal.lock().append(1, record);
            }
        }

        fn write_frame(journal: &mut Journal, record: &[u8]) {
            Journal::append(journal, 2, record);
        }

        fn pointer(journal: &mut Journal) {
            let write = Journal::append;
            write(journal, 3, &[]);
        }

        impl GrantStore {
            fn elsewhere(&self, record: &[u8]) {
                self.journal.lock().put(1, record);
            }

            fn optional(&self, applying: Option<&Applying<'_>>, record: &[u8]) {
                self.journal.lock().append(1, record);
            }

            fn quiet(&self, record: &[u8]) {
                debug_assert!(self.journal.lock().append(1, record).is_ok());
            }

            fn history(&self) -> usize {
                self.journal.lock().frames().len()
            }
        }

        #[cfg(any(test, feature = "bench"))]
        fn shipped_under_a_feature(journal: &mut Journal) {
            journal.append(4, &[]);
        }

        #[cfg(test)]
        mod tests {
            fn direct(journal: &mut Journal) {
                journal.append(1, &[]);
            }
        }
    "#;
    let scanned = scan(STORE, seeded, &seeded_rules());
    assert_eq!(scanned.writes, 1, "the one write that holds the token");
    assert_eq!(
        rules_of(&scanned.violations),
        vec![
            ("sneaky".to_owned(), "state written".to_owned()),
            ("sneaky".to_owned(), "state reached".to_owned()),
            ("write_frame".to_owned(), "state written".to_owned()),
            ("pointer".to_owned(), "state written".to_owned()),
            ("elsewhere".to_owned(), "state reached".to_owned()),
            ("optional".to_owned(), "state written".to_owned()),
            ("optional".to_owned(), "state reached".to_owned()),
            ("quiet".to_owned(), "state written".to_owned()),
            (
                "shipped_under_a_feature".to_owned(),
                "state written".to_owned()
            ),
        ]
    );
}

/// A renamed import does not hide the token, built or handed out.
#[test]
fn test_a_seeded_token_built_outside_the_engine_is_found_under_any_name() {
    let seeded = r#"
        use crate::operations::mutation::Applying as Pass;
        use crate::operations::mutation::{Applying};

        pub fn forge() -> Pass<'static> {
            Pass { operation_id: OperationId::from_bytes([0; 16]), _engine: PhantomData }
        }

        fn quietly() {
            let _ = Applying { operation_id: OperationId::from_bytes([1; 16]), _engine: PhantomData };
        }

        impl Pass<'_> {
            fn more() {}
        }

        impl Clone for Applying<'_> {
            fn clone(&self) -> Self { todo!() }
        }

        #[cfg(test)]
        fn allowed() -> Applying<'static> { todo!() }
    "#;
    let scanned = scan(
        "crates/permguard-host/src/api/grants.rs",
        seeded,
        &seeded_rules(),
    );
    assert_eq!(
        rules_of(&scanned.violations),
        vec![
            ("forge".to_owned(), "token forged".to_owned()),
            ("forge".to_owned(), "token built".to_owned()),
            ("quietly".to_owned(), "token built".to_owned()),
            ("<file>".to_owned(), "token forged".to_owned()),
            ("<file>".to_owned(), "token copied".to_owned()),
        ]
    );
}

#[test]
fn test_the_engine_may_build_its_token_and_may_not_derive_a_copy() {
    let engine = r#"
        #[derive(Debug, Clone)]
        pub struct Applying<'a> { operation_id: OperationId, _engine: PhantomData<&'a ()> }

        impl Mutations {
            pub fn run(&self) {
                let token = Applying { operation_id: id(), _engine: PhantomData };
            }
        }
    "#;
    let scanned = scan(ENGINE, engine, &seeded_rules());
    assert_eq!(
        rules_of(&scanned.violations),
        vec![("<file>".to_owned(), "token copied".to_owned())]
    );
}

#[test]
fn test_a_file_that_does_not_parse_is_reported_not_skipped() {
    let scanned = scan(STORE, "fn broken( {", &seeded_rules());
    assert_eq!(
        rules_of(&scanned.violations),
        vec![("<file>".to_owned(), "unparsed".to_owned())]
    );
}
