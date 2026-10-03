// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The log field classification of P10, enforced on the source.
//!
//! | Class        | Fields                                                                                                                      | In a log record           |
//! | ------------ | --------------------------------------------------------------------------------------------------------------------------- | ------------------------- |
//! | forbidden    | payloads, credentials, proofs, policy text, subjects, a caller's occurrence and request ids, partition and profile names    | never                     |
//! | tenant scope | `zone`, `ledger`                                                                                                            | the id only, never a name |
//! | correlation  | `request.id` and `decision.id` (drawn by this process), `stream.id`, `stream.instance`, `producer`, `instance`: bounded ids | as is                     |
//! | operational  | everything else: event names, components, counts, codes, durations, a key's realm                                           | as is                     |
//!
//! A `tracing` field is written `name = value` inside the macro, so a field is a line of that
//! shape in a scanned crate's source. A forbidden name fails; a `zone` or `ledger` field whose
//! value reads a name fails. Fields of the audit channel (`audit.*`) are audit records, not
//! telemetry, and keep their own rule: the subject is pseudonymized or masked.

#![allow(clippy::expect_used)]

use std::path::Path;

const FORBIDDEN: &[&str] = &[
    "subject",
    "principal",
    "event_id",
    "partition",
    "payload",
    "body",
    "token",
    "secret",
    "password",
    "credential",
    "proof",
    "policy_text",
    "tenant",
    "profile",
    "zone_name",
    "ledger_name",
    // A caller's own name for its request; the log carries `request.id`, which this process drew.
    "request_id",
];

/// What a `zone` or `ledger` field's value may not read: a name. (The Data Plane's authorization
/// mirror logs itself through `log_id()`, ids only, and names itself to a person through
/// `display_name()`; the H-13 test in `authz_decision.rs` proves no name reaches a log line.)
const NAME_READS: &[&str] = &[".name", "_name", "display_name"];

fn walk(directory: &Path, found: &mut Vec<(String, usize, String)>) {
    let Ok(entries) = std::fs::read_dir(directory) else {
        return;
    };
    for entry in entries.filter_map(Result::ok) {
        let path = entry.path();
        if path.is_dir() {
            walk(&path, found);
        } else if path.extension().is_some_and(|extension| extension == "rs") {
            let text = std::fs::read_to_string(&path).expect("a source file reads");
            for (index, line) in text.lines().enumerate() {
                found.push((path.display().to_string(), index + 1, line.to_owned()));
            }
        }
    }
}

/// `(name, value)` when `line` is a `tracing` field: an identifier, ` = `, a value, a comma. A
/// macro written on one line, `warn!(zone = x, "…")`, is read from its opening parenthesis.
fn field(line: &str) -> Option<(&str, &str)> {
    let trimmed = line.trim();
    let trimmed = ["trace!(", "debug!(", "info!(", "warn!(", "error!("]
        .iter()
        .find_map(|opening| trimmed.split_once(opening).map(|(_, rest)| rest))
        .unwrap_or(trimmed);
    let (name, value) = trimmed.split_once(" = ")?;
    let value = value
        .strip_suffix(',')
        .or_else(|| value.split_once(", ").map(|(value, _)| value))?;
    let plain = name
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '.');
    (plain && !name.is_empty() && !trimmed.starts_with("let ") && !trimmed.starts_with("//"))
        .then_some((name, value))
}

#[test]
fn test_no_log_field_carries_a_forbidden_value_or_a_tenant_name() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let mut lines = Vec::new();
    for owner in std::fs::read_dir(root.join("crates")).expect("the crates list") {
        let owner = owner.expect("a crate").path();
        walk(&owner.join("src"), &mut lines);
    }

    let mut problems = Vec::new();
    for (file, number, line) in &lines {
        let Some((name, value)) = field(line) else {
            continue;
        };
        // The audit channel has its own rules: its subject is rendered through the pseudonymizer,
        // masked when there is none, never written as it arrived.
        if name.starts_with("audit.") {
            continue;
        }
        let last = name.rsplit('.').next().unwrap_or(name);
        if FORBIDDEN.contains(&name) || FORBIDDEN.contains(&last) {
            problems.push(format!(
                "{file}:{number}: `{name}` is a forbidden log field"
            ));
        }
        let name = last;
        if (name == "zone" || name == "ledger")
            && NAME_READS.iter().any(|read| value.contains(read))
        {
            problems.push(format!("{file}:{number}: `{name}` logs a name; log the id"));
        }
    }

    assert!(
        problems.is_empty(),
        "P10 log classification:\n  {}",
        problems.join("\n  ")
    );
    assert!(lines.len() > 10_000, "the scan read the sources");
}

#[test]
fn test_the_field_reader_tells_a_field_from_other_code() {
    assert_eq!(
        field("    zone = zone.id.as_str(),"),
        Some(("zone", "zone.id.as_str()"))
    );
    assert_eq!(
        field("    event.name = \"x\","),
        Some(("event.name", "\"x\""))
    );
    assert_eq!(
        field("    warn!(zone = zone.name(), \"a zone\");"),
        Some(("zone", "zone.name()"))
    );
    assert_eq!(field("    let zone = x,"), None);
    assert_eq!(field("    zone = x;"), None);
}
