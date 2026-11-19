// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! Which Host a key witness speaks for (BUG-0079, DEC-0035).
//!
//! The audit pseudonym key and the zone keys are derived per Host, from its `host_id`. A witness
//! records, per version label, what the key behind that label produces for a fixed input, so a key
//! changed without its label is refused before it writes an ambiguous record. An identity reset
//! changes the `host_id`, and with it every derivation, while the configured labels stay: under
//! the new Host, `v1` names a new key, and the records before and after the reset are told apart by
//! the Host that wrote them. So a witness is the Host's: an entry is `<version>@<host_id>`.
//!
//! | Entry for the version                            | Witness now            | Outcome                                      |
//! | ------------------------------------------------ | ---------------------- | -------------------------------------------- |
//! | `<version>@<this host_id>`                       | the same               | holds                                        |
//! | `<version>@<this host_id>`                       | another                | refused: the key changed under its label     |
//! | `<version>`, written before entries named a Host | the same               | adopted as this Host's                       |
//! | `<version>`, written before entries named a Host | another, after a reset | the retired identity's; this Host's recorded |
//! | `<version>`, written before entries named a Host | another, no reset      | refused: the key changed under its label     |
//! | none                                             |                        | this Host's recorded                         |

use std::path::Path;

/// The Host a witness is checked for: its `host_id`, and whether a reset ever retired an identity
/// on its volume.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostScope {
    pub host_id: String,
    pub reset: bool,
}

impl HostScope {
    /// The scope of the Host `host_id` on the volume at `root`: reset when `host/identity/retired/`
    /// holds an identity.
    pub fn of(root: &Path, host_id: &[u8; 16]) -> Self {
        let retired = root
            .join(crate::storage::volume::HOST)
            .join("identity")
            .join(super::reset::RETIRED);
        let reset = std::fs::read_dir(retired)
            .map(|mut entries| entries.any(|entry| entry.is_ok()))
            .unwrap_or(false);
        Self {
            host_id: super::record::uuid_text(host_id),
            reset,
        }
    }

    fn label(&self, version: &str) -> String {
        format!("{version}@{}", self.host_id)
    }
}

/// What a check found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Witnessed {
    /// The version's entry for this Host holds the same witness.
    Holds,
    /// The version is new for this Host: its entry was added.
    Recorded,
    /// The version names another key for this Host than the one it witnessed.
    KeyChanged,
}

/// Checks `witness` for `version` against `entries` under `scope`, updating them: an entry added,
/// a legacy one adopted or attributed to the retired identity. `same` says whether two witnesses
/// name one key. With no `scope`, a process that knows no Host identity, the entries are by
/// version alone, as before they named a Host. Answers the outcome and whether `entries` changed.
pub fn check(
    entries: &mut Vec<(String, String)>,
    version: &str,
    witness: &str,
    scope: Option<&HostScope>,
    same: impl Fn(&str, &str) -> bool,
) -> (Witnessed, bool) {
    let Some(scope) = scope else {
        return match entries.iter().find(|(known, _)| known == version) {
            Some((_, held)) if same(held, witness) => (Witnessed::Holds, false),
            Some(_) => (Witnessed::KeyChanged, false),
            None => {
                entries.push((version.to_owned(), witness.to_owned()));
                (Witnessed::Recorded, true)
            }
        };
    };
    let label = scope.label(version);
    if let Some((_, held)) = entries.iter().find(|(known, _)| *known == label) {
        let outcome = if same(held, witness) {
            Witnessed::Holds
        } else {
            Witnessed::KeyChanged
        };
        return (outcome, false);
    }
    if let Some(at) = entries.iter().position(|(known, _)| known == version) {
        if same(&entries[at].1, witness) {
            entries[at].0 = label;
            return (Witnessed::Holds, true);
        }
        if !scope.reset {
            return (Witnessed::KeyChanged, false);
        }
        entries[at].0 = format!("{version}@retired");
    }
    entries.push((label, witness.to_owned()));
    (Witnessed::Recorded, true)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scope(host: &str, reset: bool) -> HostScope {
        HostScope {
            host_id: host.to_owned(),
            reset,
        }
    }

    fn equal(left: &str, right: &str) -> bool {
        left == right
    }

    #[test]
    fn a_witness_is_the_hosts_and_a_reset_starts_the_new_hosts_own() {
        let mut entries = Vec::new();
        let a = scope("host-a", false);
        assert_eq!(
            check(&mut entries, "v1", "k1", Some(&a), equal),
            (Witnessed::Recorded, true)
        );
        assert_eq!(
            check(&mut entries, "v1", "k1", Some(&a), equal),
            (Witnessed::Holds, false)
        );
        assert_eq!(
            check(&mut entries, "v1", "k2", Some(&a), equal).0,
            Witnessed::KeyChanged
        );
        // After a reset the new Host's `v1` is its own key, recorded beside the old one.
        let b = scope("host-b", true);
        assert_eq!(
            check(&mut entries, "v1", "k2", Some(&b), equal),
            (Witnessed::Recorded, true)
        );
        assert_eq!(
            check(&mut entries, "v1", "k2", Some(&b), equal),
            (Witnessed::Holds, false)
        );
        assert_eq!(
            check(&mut entries, "v1", "k3", Some(&b), equal).0,
            Witnessed::KeyChanged
        );
        assert_eq!(
            entries,
            vec![
                ("v1@host-a".to_owned(), "k1".to_owned()),
                ("v1@host-b".to_owned(), "k2".to_owned()),
            ]
        );
    }

    #[test]
    fn a_legacy_entry_is_adopted_attributed_to_the_retired_identity_or_refused() {
        let legacy = || vec![("v1".to_owned(), "k1".to_owned())];
        // The same key: this Host's, named so from now on.
        let mut entries = legacy();
        assert_eq!(
            check(
                &mut entries,
                "v1",
                "k1",
                Some(&scope("host-a", false)),
                equal
            ),
            (Witnessed::Holds, true)
        );
        assert_eq!(entries, vec![("v1@host-a".to_owned(), "k1".to_owned())]);
        // Another key with no reset: the label was reused for a new key.
        let mut entries = legacy();
        assert_eq!(
            check(
                &mut entries,
                "v1",
                "k2",
                Some(&scope("host-a", false)),
                equal
            ),
            (Witnessed::KeyChanged, false)
        );
        assert_eq!(entries, legacy(), "nothing written on a refusal");
        // Another key after a reset: the retired identity's, and the new Host's recorded.
        let mut entries = legacy();
        assert_eq!(
            check(
                &mut entries,
                "v1",
                "k2",
                Some(&scope("host-b", true)),
                equal
            ),
            (Witnessed::Recorded, true)
        );
        assert_eq!(
            entries,
            vec![
                ("v1@retired".to_owned(), "k1".to_owned()),
                ("v1@host-b".to_owned(), "k2".to_owned()),
            ]
        );
    }

    #[test]
    fn a_scope_knows_a_reset_from_the_retired_identities_on_the_volume() {
        let root = std::env::temp_dir().join(format!("pg-witness-scope-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let retired = root.join("host/identity/retired");
        std::fs::create_dir_all(&retired).expect("created");
        assert!(!HostScope::of(&root, &[1; 16]).reset, "an empty directory");
        std::fs::create_dir_all(retired.join("0101")).expect("created");
        let scope = HostScope::of(&root, &[1; 16]);
        assert!(scope.reset);
        assert_eq!(scope.host_id, super::super::record::uuid_text(&[1; 16]));
        let _ = std::fs::remove_dir_all(&root);
    }
}
