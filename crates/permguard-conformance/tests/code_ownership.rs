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
    "6-contracts/0-interfaces-model.md",
    "6-contracts/1-contract-pdp-native-v1.md",
    "6-contracts/2-contract-pdp-temporal-v1alpha1.md",
    "6-contracts/3-contract-evidence-decisions.md",
    "6-contracts/4-contract-evidence-events.md",
    "6-contracts/5-contract-stream-common.md",
    "6-contracts/6-contract-ledger-notp.md",
    "6-contracts/7-contract-catalog-discovery.md",
    "6-contracts/8-contract-host-api.md",
    "5-command-line/1-command-line.md",
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

/// Codes answered with a status their class does not map to, each an open finding in the status
/// file. The list only shrinks.
const STATUS_OVERRIDES: [(&str, u64); 1] = [("stream.OFFSET_EXPIRED", 410)];

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
