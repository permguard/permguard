// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The stable-code ownership report, `contracts/codes.json`, against `permguard_core::codes`.
//!
//! Every registered code has exactly one entry, naming the one document that owns it — a contract,
//! the command line, or the storage document for the storage library's incident codes — how it
//! travels and the class it is answered with. A code registered without an owner, an owner for
//! a code no longer registered, or a compatibility-only code outside `legacy` fails here.

use std::collections::{BTreeMap, BTreeSet};

use permguard_core::codes;
use serde_json::Value;

/// The documents that own codes, as paths under the architecture knowledge base.
const CONTRACTS: [&str; 12] = [
    "1-architecture/8-architecture-storage-operations.md",
    "7-contracts/0-interfaces-model.md",
    "7-contracts/1-contract-pdp-native-v1.md",
    "7-contracts/2-contract-pdp-temporal-v1alpha1.md",
    "7-contracts/3-contract-evidence-decisions.md",
    "7-contracts/4-contract-evidence-events.md",
    "7-contracts/5-contract-stream-common.md",
    "7-contracts/6-contract-ledger-notp.md",
    "7-contracts/7-contract-catalog-discovery.md",
    "7-contracts/8-contract-host-api.md",
    "6-command-line/1-command-line.md",
    "legacy",
];

const KINDS: [&str; 7] = [
    "refusal", "denial", "reason", "ack", "log", "local", "unused",
];

const CLASSES: [&str; 5] = [
    "validation",
    "conflict",
    "not_found",
    "unavailable",
    "internal",
];

/// Codes answered with two classes today, each an open finding in the status file. The list only
/// shrinks: a new code with two classes fails here.
const TWO_CLASSES: [&str; 2] = ["client.HTTP_STATUS", "pdp_temporal.EVENT_NOT_CANONICAL"];

/// Codes answered with a status their class does not map to: an open finding in the status file,
/// or a status HTTP itself names for the refusal. The list only shrinks but for the second kind.
const STATUS_OVERRIDES: [(&str, u64); 2] = [
    ("stream.OFFSET_EXPIRED", 410),
    // RFC 6585: a head of too many fields is `431`, whatever the class (BUG-0329).
    ("common.HEADER_FIELDS_EXCEEDED", 431),
];

fn report() -> BTreeMap<String, Value> {
    let path = permguard_conformance::contracts::root().join("codes.json");
    let text = std::fs::read_to_string(&path).expect("the report is checked in");
    let value: Value = serde_json::from_str(&text).expect("the report is JSON");
    value["codes"]
        .as_object()
        .expect("`codes` is an object")
        .iter()
        .map(|(name, entry)| (name.clone(), entry.clone()))
        .collect()
}

#[test]
fn test_every_registered_code_has_exactly_one_owner_and_nothing_else_does() {
    let report = report();
    let registered: BTreeMap<String, &str> = codes::all()
        .into_iter()
        .map(|(name, value)| (name.to_owned(), value))
        .collect();

    let reported: BTreeSet<&String> = report.keys().collect();
    let known: BTreeSet<&String> = registered.keys().collect();
    assert_eq!(
        reported.difference(&known).collect::<Vec<_>>(),
        Vec::<&&String>::new(),
        "owners for codes that are not registered"
    );
    assert_eq!(
        known.difference(&reported).collect::<Vec<_>>(),
        Vec::<&&String>::new(),
        "registered codes without an owner"
    );
    for (name, value) in &registered {
        assert_eq!(
            report[name]["code"], *value,
            "{name} names another spelling"
        );
    }
}

#[test]
fn test_every_entry_names_a_contract_a_kind_and_the_class_it_is_answered_with() {
    for (name, entry) in report() {
        let contract = entry["contract"].as_str().unwrap_or_default();
        assert!(
            !contract.is_empty() && CONTRACTS.contains(&contract),
            "{name}: `{contract}` is not a contract document that owns codes"
        );
        let kind = entry["kind"].as_str().unwrap_or_default();
        assert!(KINDS.contains(&kind), "{name}: `{kind}` is not a kind");

        let answered = matches!(kind, "refusal" | "local");
        let classes: Vec<&str> = match (entry.get("class"), entry.get("classes")) {
            (Some(one), None) => vec![one.as_str().unwrap_or_default()],
            (None, Some(many)) => many
                .as_array()
                .map(|many| many.iter().filter_map(Value::as_str).collect())
                .unwrap_or_default(),
            (None, None) => Vec::new(),
            (Some(_), Some(_)) => panic!("{name}: `class` and `classes` together"),
        };
        assert_eq!(
            !classes.is_empty(),
            answered,
            "{name}: a class belongs to a refusal or a local failure, and only there"
        );
        for class in &classes {
            assert!(CLASSES.contains(class), "{name}: `{class}` is not a class");
        }
        if classes.len() > 1 {
            assert!(
                TWO_CLASSES.contains(&name.as_str()),
                "{name}: answered with two classes and not a recorded finding"
            );
        }

        if let Some(status) = entry.get("http") {
            assert!(
                STATUS_OVERRIDES
                    .iter()
                    .any(|(code, expected)| *code == name && status.as_u64() == Some(*expected)),
                "{name}: a status override that is not a recorded finding"
            );
        }

        let legacy = name.starts_with("legacy.");
        assert_eq!(
            entry.get("compatibility_only") == Some(&Value::Bool(true)),
            legacy,
            "{name}: compatibility-only exactly when it is a legacy code"
        );
        assert_eq!(
            contract == "legacy",
            legacy,
            "{name}: a legacy code has no contract"
        );
        if legacy {
            assert_eq!(
                kind, "unused",
                "{name}: a compatibility-only code is never generated"
            );
        }
    }
}

/// Every Rust source of the workspace's crates, test sources and the registry itself left out.
fn sources(dir: &std::path::Path, into: &mut Vec<std::path::PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let name = entry.file_name().to_string_lossy().into_owned();
        if path.is_dir() {
            if !matches!(name.as_str(), "tests" | "target" | "benches" | "fuzz") {
                sources(&path, into);
            }
        } else if name.ends_with(".rs")
            && name != "tests.rs"
            && !path.ends_with("permguard-core/src/codes.rs")
        {
            into.push(path);
        }
    }
}

/// BUG-0176: a code registered `unused` is produced by no path: the moment one is, its entry must
/// say how it travels, or this fails. Read from the code, so the report cannot fall behind it.
#[test]
fn test_a_code_registered_unused_is_referenced_by_no_source() {
    let crates = permguard_conformance::contracts::root()
        .parent()
        .expect("the repository")
        .join("crates");
    let mut files = Vec::new();
    sources(&crates, &mut files);
    let texts: Vec<(std::path::PathBuf, String)> = files
        .into_iter()
        .filter_map(|path| std::fs::read_to_string(&path).ok().map(|text| (path, text)))
        .collect();
    let mut produced = Vec::new();
    for (name, entry) in report() {
        if entry["kind"] != "unused" || name.starts_with("legacy.") {
            continue;
        }
        let Some((module, constant)) = name.split_once('.') else {
            continue;
        };
        let path = format!("{module}::{constant}");
        let users: Vec<_> = texts
            .iter()
            .filter(|(_, text)| text.contains(&path))
            .map(|(file, _)| file.display().to_string())
            .collect();
        if !users.is_empty() {
            produced.push(format!("{name}: {users:?}"));
        }
    }
    assert!(
        produced.is_empty(),
        "registered `unused` and produced by these sources:\n{}",
        produced.join("\n")
    );
}
