// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! What this plane follows, with the patterns compiled.
//!
//! The declaration lives in the configuration ([`permguard_core::mirrors`]); deciding whether a
//! name matches is behaviour, and behaviour belongs to the plane that mirrors. Every source is a
//! `policy.mirror` task: one of a membership, its scope the coordinator's signed selector, or the
//! local task of a process hosting both Planes (WP-7.7). The file only narrows them. Patterns are
//! **anchored**: `main` follows the ledger `main` and not `main-staging`, because a configuration
//! an operator cannot predict is a configuration that eventually follows something nobody asked
//! for.

use anyhow::{Context, Result};
use permguard_host::composition::MirrorTask;
use permguard_host::membership::local;

/// A set of name patterns. Empty means everything — so an absent list and a
/// `.*` behave the same, and neither is a special case anywhere downstream.
#[derive(Debug, Clone, Default)]
struct Patterns {
    written: Vec<String>,
    compiled: Vec<regex::Regex>,
}

impl Patterns {
    fn compile(written: &[String], what: &str) -> Result<Self> {
        let compiled = written
            .iter()
            .map(|pattern| {
                regex::Regex::new(&format!("^(?:{pattern})$"))
                    .with_context(|| format!("reading the {what} pattern `{pattern}`"))
            })
            .collect::<Result<Vec<_>>>()?;

        Ok(Self {
            written: written.to_vec(),
            compiled,
        })
    }

    fn matches(&self, name: &str) -> bool {
        self.compiled.is_empty() || self.compiled.iter().any(|pattern| pattern.is_match(name))
    }

    fn describe(&self) -> String {
        if self.written.is_empty() {
            "*".to_owned()
        } else {
            self.written.join(",")
        }
    }
}

/// How the file narrows the `policy.mirror` tasks this plane follows. `mirrors.tasks` narrows the
/// membership tasks (WP-7.2a): empty, every one is followed whole, its signed selector being the
/// scope; naming any, only those named are followed. `mirrors.local` narrows the local task
/// (WP-7.7), which is always followed.
#[derive(Debug, Clone, Default)]
pub struct TaskSelections {
    selections: Vec<TaskSelection>,
    local: Option<(Patterns, Patterns)>,
}

#[derive(Debug, Clone)]
struct TaskSelection {
    membership: String,
    task: String,
    zones: Patterns,
    ledgers: Patterns,
}

impl TaskSelections {
    /// Compiles the declared narrowing, refusing a broken pattern at startup.
    pub fn compile(
        inputs: &[permguard_core::mirrors::MirrorTaskSelection],
        local: Option<&permguard_core::mirrors::MirrorLocal>,
    ) -> Result<Self> {
        Ok(Self {
            selections: inputs
                .iter()
                .map(|input| {
                    Ok(TaskSelection {
                        membership: input.membership.clone(),
                        task: input.task.clone(),
                        zones: Patterns::compile(&input.zones, "zone")?,
                        ledgers: Patterns::compile(&input.ledgers, "ledger")?,
                    })
                })
                .collect::<Result<_>>()?,
            local: local
                .map(|local| {
                    Ok::<_, anyhow::Error>((
                        Patterns::compile(&local.zones, "zone")?,
                        Patterns::compile(&local.ledgers, "ledger")?,
                    ))
                })
                .transpose()?,
        })
    }

    /// Whether the task `task` of membership `membership` is followed at all: the local task
    /// always.
    pub fn follows_task(&self, membership: &[u8; 16], task: &str) -> bool {
        is_local(membership, task)
            || self.selections.is_empty()
            || self.selection(membership, task).is_some()
    }

    /// Whether a ledger the task lists, by its names, is followed.
    pub fn follows(&self, membership: &[u8; 16], task: &str, zone: &str, ledger: &str) -> bool {
        if is_local(membership, task) {
            return self
                .local
                .as_ref()
                .is_none_or(|(zones, ledgers)| zones.matches(zone) && ledgers.matches(ledger));
        }
        if self.selections.is_empty() {
            return true;
        }
        self.selection(membership, task).is_some_and(|selection| {
            selection.zones.matches(zone) && selection.ledgers.matches(ledger)
        })
    }

    /// What the local task follows, for a log line that has to be readable.
    pub fn local_patterns(&self) -> (String, String) {
        self.local.as_ref().map_or_else(
            || ("*".to_owned(), "*".to_owned()),
            |(zones, ledgers)| (zones.describe(), ledgers.describe()),
        )
    }

    /// Warns of every narrowing that names no task this Host holds: a mistyped id follows
    /// nothing, and says so rather than staying silent.
    pub fn report_unmatched(&self, held: &[MirrorTask]) {
        for selection in &self.selections {
            let matched = held.iter().any(|task| {
                permguard_host::identity::record::uuid_text(&task.membership_id)
                    == selection.membership
                    && task.task_id == selection.task
            });
            if !matched {
                tracing::warn!(
                    event.name = "sync.task_unmatched",
                    component = "data-plane",
                    membership = selection.membership.as_str(),
                    task = selection.task.as_str(),
                    "`mirrors.tasks` names a task no active membership of this Host holds"
                );
            }
        }
        if self.local.is_some() && !held.iter().any(local::is_local) {
            tracing::warn!(
                event.name = "sync.task_unmatched",
                component = "data-plane",
                task = local::LOCAL_TASK,
                "`mirrors.local` narrows the local task, which only a process hosting both Planes \
                 has"
            );
        }
    }

    fn selection(&self, membership: &[u8; 16], task: &str) -> Option<&TaskSelection> {
        let membership = permguard_host::identity::record::uuid_text(membership);
        self.selections
            .iter()
            .find(|selection| selection.membership == membership && selection.task == task)
    }
}

fn is_local(membership: &[u8; 16], task: &str) -> bool {
    *membership == local::LOCAL_MEMBERSHIP && task == local::LOCAL_TASK
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;
    use permguard_core::mirrors::{MirrorLocal, MirrorTaskSelection};

    const MEMBERSHIP: [u8; 16] = [7; 16];

    fn local(zones: &[&str], ledgers: &[&str]) -> TaskSelections {
        TaskSelections::compile(
            &[],
            Some(&MirrorLocal {
                zones: zones.iter().map(|p| (*p).to_owned()).collect(),
                ledgers: ledgers.iter().map(|p| (*p).to_owned()).collect(),
            }),
        )
        .expect("the narrowing compiles")
    }

    fn follows_local(selections: &TaskSelections, zone: &str, ledger: &str) -> bool {
        selections.follows(&local::LOCAL_MEMBERSHIP, local::LOCAL_TASK, zone, ledger)
    }

    #[test]
    fn no_pattern_follows_everything() {
        let every = TaskSelections::compile(&[], None).expect("compiles");
        assert!(every.follows_task(&local::LOCAL_MEMBERSHIP, local::LOCAL_TASK));
        assert!(follows_local(&every, "acme", "anything"));
        assert_eq!(every.local_patterns(), ("*".to_owned(), "*".to_owned()));
        assert!(follows_local(&local(&[], &[]), "acme", "anything"));
    }

    #[test]
    fn patterns_describe_whole_names() {
        let followed = local(&["acme-.*"], &["main"]);

        assert!(follows_local(&followed, "acme-eu", "main"));
        assert!(
            !follows_local(&followed, "not-acme-eu", "main"),
            "anchored at the start"
        );
        assert!(
            !follows_local(&followed, "acme-eu", "main-staging"),
            "anchored at the end: `main` is not a prefix"
        );
        assert_eq!(
            followed.local_patterns(),
            ("acme-.*".to_owned(), "main".to_owned())
        );
    }

    #[test]
    fn several_patterns_are_alternatives() {
        let followed = local(&["eu", "us"], &[]);

        assert!(follows_local(&followed, "eu", "main"));
        assert!(follows_local(&followed, "us", "main"));
        assert!(!follows_local(&followed, "apac", "main"));
    }

    #[test]
    fn a_broken_pattern_is_refused_where_somebody_is_watching() {
        let error = TaskSelections::compile(
            &[],
            Some(&MirrorLocal {
                zones: vec!["acme-[".to_owned()],
                ledgers: Vec::new(),
            }),
        )
        .expect_err("a broken pattern cannot compile")
        .to_string();

        assert!(error.contains("zone pattern `acme-[`"), "{error}");
    }

    /// WP-7.7: narrowing the membership tasks never leaves the local task out, and narrowing the
    /// local task never narrows a membership's.
    #[test]
    fn the_local_task_and_the_membership_tasks_are_narrowed_apart() {
        let selections = TaskSelections::compile(
            &[MirrorTaskSelection {
                membership: permguard_host::identity::record::uuid_text(&MEMBERSHIP),
                task: "mirror".to_owned(),
                zones: vec!["acme".to_owned()],
                ledgers: Vec::new(),
            }],
            Some(&MirrorLocal {
                zones: vec!["local-zone".to_owned()],
                ledgers: Vec::new(),
            }),
        )
        .expect("compiles");
        assert!(selections.follows_task(&local::LOCAL_MEMBERSHIP, local::LOCAL_TASK));
        assert!(selections.follows_task(&MEMBERSHIP, "mirror"));
        assert!(!selections.follows_task(&MEMBERSHIP, "other"));
        assert!(follows_local(&selections, "local-zone", "main"));
        assert!(!follows_local(&selections, "acme", "main"));
        assert!(selections.follows(&MEMBERSHIP, "mirror", "acme", "main"));
        assert!(!selections.follows(&MEMBERSHIP, "mirror", "local-zone", "main"));
        // A membership whose id is not the nil one is never the local task, whatever its name.
        assert!(!selections.follows_task(&MEMBERSHIP, local::LOCAL_TASK));
    }
}
