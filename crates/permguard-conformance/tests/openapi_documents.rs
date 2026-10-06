// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! Every OpenAPI document of `contracts/openapi/` is well formed: OpenAPI 3.1 over JSON Schema
//! 2020-12, every `$ref` resolves, every operation is named and answers, and every object schema
//! says whether it is closed. The wire types are checked against the documents by the tests of the
//! crates that own them.

use std::collections::BTreeSet;
use std::fs;

use permguard_conformance::schema::Document;
use serde_json::Value;

/// The documents the REST surfaces are described by; a new file must be listed here.
const DOCUMENTS: [&str; 11] = [
    "catalog.json",
    "common.json",
    "discovery.json",
    "evidence-decisions.json",
    "evidence-events-v1alpha1.json",
    "health.json",
    "host.json",
    "notp.json",
    "pdp-native-v1.json",
    "pdp-temporal-v1alpha1.json",
    "stream-common.json",
];

const METHODS: [&str; 5] = ["get", "post", "put", "patch", "delete"];

#[test]
fn test_the_document_list_is_the_directory() {
    let directory = permguard_conformance::contracts::root().join("openapi");
    let found: BTreeSet<String> = fs::read_dir(&directory)
        .expect("the directory is checked in")
        .flatten()
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .collect();
    let listed: BTreeSet<String> = DOCUMENTS.iter().map(|name| (*name).to_owned()).collect();
    assert_eq!(found, listed);
}

#[test]
fn test_every_document_is_openapi_3_1_over_json_schema_2020_12() {
    for name in DOCUMENTS {
        let document = Document::load(name);
        let value = document.value();
        assert_eq!(value["openapi"], "3.1.0", "{name}");
        assert_eq!(
            value["jsonSchemaDialect"], "https://json-schema.org/draft/2020-12/schema",
            "{name}"
        );
        assert!(value["info"]["title"].is_string(), "{name}: no title");
        assert!(value["paths"].is_object(), "{name}: no paths");
    }
}

#[test]
fn test_every_operation_is_named_and_answers() {
    let mut operation_ids = BTreeSet::new();
    for name in DOCUMENTS {
        let document = Document::load(name);
        let paths = document.value()["paths"]
            .as_object()
            .cloned()
            .unwrap_or_default();
        for (path, item) in paths {
            for method in METHODS {
                let Some(operation) = item.get(method) else {
                    continue;
                };
                let id = operation["operationId"]
                    .as_str()
                    .unwrap_or_else(|| panic!("{name} {method} {path}: no operationId"));
                assert!(
                    operation_ids.insert(id.to_owned()),
                    "{name}: `{id}` names two operations"
                );
                let responses = operation["responses"].as_object();
                assert!(
                    responses.is_some_and(|responses| !responses.is_empty()),
                    "{name} {method} {path}: no responses"
                );
            }
        }
    }
}

#[test]
fn test_every_reference_resolves_and_every_object_says_whether_it_is_closed() {
    for name in DOCUMENTS {
        let document = Document::load(name);
        let mut offences = Vec::new();
        walk(document.value(), name, "$", &mut offences);
        assert!(offences.is_empty(), "{name}:\n{}", offences.join("\n"));
    }
}

fn walk(value: &Value, name: &str, at: &str, offences: &mut Vec<String>) {
    match value {
        Value::Object(members) => {
            if let Some(reference) = members.get("$ref").and_then(Value::as_str) {
                let (file, pointer) = reference.split_once('#').unwrap_or((reference, ""));
                let file = if file.is_empty() { name } else { file };
                let target = permguard_conformance::contracts::root()
                    .join("openapi")
                    .join(file);
                let resolved = fs::read_to_string(&target)
                    .ok()
                    .and_then(|text| serde_json::from_str::<Value>(&text).ok())
                    .is_some_and(|document| document.pointer(pointer).is_some());
                if !resolved {
                    offences.push(format!("{at}: `{reference}` resolves to nothing"));
                }
            }
            if members.get("type") == Some(&Value::String("object".to_owned()))
                && members.contains_key("properties")
                && !members.contains_key("additionalProperties")
            {
                offences.push(format!(
                    "{at}: an object schema that does not say whether it is closed"
                ));
            }
            for (key, member) in members {
                walk(member, name, &format!("{at}.{key}"), offences);
            }
        }
        Value::Array(items) => {
            for (index, item) in items.iter().enumerate() {
                walk(item, name, &format!("{at}[{index}]"), offences);
            }
        }
        _ => {}
    }
}

/// The keyword check runs over every schema of every document, not only where a value reaches.
#[test]
fn test_no_document_uses_a_keyword_this_check_does_not_enforce() {
    for name in DOCUMENTS {
        let document = Document::load(name);
        let found = permguard_conformance::schema::unenforced_keywords(document.value());
        assert!(found.is_empty(), "{name}:\n{}", found.join("\n"));
    }
}
