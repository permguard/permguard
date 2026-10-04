// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The checked-in OpenAPI documents of `contracts/openapi/`, and a validator for the part of JSON
//! Schema 2020-12 they are written in.
//!
//! A REST surface's wire types are checked against its document both ways: every value a type
//! serialises must validate, so the type cannot carry a member the schema does not name; and every
//! member the schema declares must be seen in at least one validated value, so the schema cannot
//! name a member the type no longer has. [`Document::assert_covered`] makes the second check.
//!
//! The validator knows a closed set of keywords and refuses a schema that uses any other, so a
//! document cannot state a constraint this check silently ignores.

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

use serde::Serialize;
use serde_json::Value;

/// Keywords that annotate and constrain nothing.
const ANNOTATIONS: [&str; 7] = [
    "description",
    "title",
    "format",
    "examples",
    "deprecated",
    "readOnly",
    "writeOnly",
];

/// Keywords the validator enforces.
const ASSERTIONS: [&str; 16] = [
    "$ref",
    "type",
    "properties",
    "required",
    "additionalProperties",
    "items",
    "enum",
    "const",
    "oneOf",
    "anyOf",
    "minimum",
    "maximum",
    "minItems",
    "maxItems",
    "minLength",
    "maxLength",
];

/// One OpenAPI document and the documents its `$ref`s reach.
pub struct Document {
    name: String,
    documents: BTreeMap<String, Value>,
    seen: RefCell<BTreeMap<String, BTreeSet<String>>>,
}

impl Document {
    /// Loads `contracts/openapi/<name>` and every sibling document it refers to.
    pub fn load(name: &str) -> Self {
        let directory = crate::contracts::root().join("openapi");
        let mut documents = BTreeMap::new();
        let mut pending = vec![name.to_owned()];
        while let Some(file) = pending.pop() {
            if documents.contains_key(&file) {
                continue;
            }
            let value = read(&directory.join(&file));
            let mut references = Vec::new();
            collect_references(&value, &mut references);
            for reference in references {
                if let Some((other, _)) = reference.split_once('#')
                    && !other.is_empty()
                {
                    pending.push(other.to_owned());
                }
            }
            documents.insert(file, value);
        }
        Self {
            name: name.to_owned(),
            documents,
            seen: RefCell::new(BTreeMap::new()),
        }
    }

    /// The document as JSON.
    pub fn value(&self) -> &Value {
        &self.documents[&self.name]
    }

    /// Validates the serialisation of `value` against the component schema `schema`.
    ///
    /// # Panics
    ///
    /// When the value does not validate, naming every violation.
    pub fn check<T: Serialize>(&self, schema: &str, value: &T) {
        let json = serde_json::to_value(value).expect("a wire type serialises to JSON");
        self.check_json(schema, &json);
    }

    /// Validates `json` against the component schema `schema`.
    ///
    /// # Panics
    ///
    /// When the value does not validate.
    pub fn check_json(&self, schema: &str, json: &Value) {
        let mut errors = Vec::new();
        let reference = format!("#/components/schemas/{schema}");
        self.validate(&self.name, &reference, json, "$", &mut errors);
        assert!(
            errors.is_empty(),
            "{}: `{schema}` refuses {json}:\n{}",
            self.name,
            errors.join("\n")
        );
    }

    /// Whether `json` validates against `schema`, without recording coverage: for negative cases.
    pub fn accepts_json(&self, schema: &str, json: &Value) -> bool {
        let saved = self.seen.borrow().clone();
        let mut errors = Vec::new();
        let reference = format!("#/components/schemas/{schema}");
        self.validate(&self.name, &reference, json, "$", &mut errors);
        *self.seen.borrow_mut() = saved;
        errors.is_empty()
    }

    /// Asserts that every property every component schema of this document declares was seen in a
    /// validated value, so the schema names no member the wire types lack.
    ///
    /// # Panics
    ///
    /// Naming each declared and never seen property.
    pub fn assert_covered(&self) {
        let seen = self.seen.borrow();
        let mut missing = Vec::new();
        let schemas = self.value()["components"]["schemas"]
            .as_object()
            .cloned()
            .unwrap_or_default();
        for (name, schema) in &schemas {
            let key = format!("{}#/components/schemas/{name}", self.name);
            let Some(properties) = schema.get("properties").and_then(Value::as_object) else {
                continue;
            };
            for property in properties.keys() {
                if !seen.get(&key).is_some_and(|names| names.contains(property)) {
                    missing.push(format!("{name}.{property}"));
                }
            }
        }
        assert!(
            missing.is_empty(),
            "{}: declared and never seen in a checked value:\n{}",
            self.name,
            missing.join("\n")
        );
    }

    fn resolve(&self, base: &str, reference: &str) -> (String, String, Value) {
        let (file, pointer) = reference
            .split_once('#')
            .expect("a reference has a fragment");
        let file = if file.is_empty() {
            base.to_owned()
        } else {
            file.to_owned()
        };
        let document = self
            .documents
            .get(&file)
            .unwrap_or_else(|| panic!("`{reference}` names a document that is not loaded"));
        let schema = document
            .pointer(pointer)
            .unwrap_or_else(|| panic!("`{reference}` resolves to nothing"))
            .clone();
        let key = format!("{file}#{pointer}");
        (file, key, schema)
    }

    fn validate(
        &self,
        base: &str,
        reference: &str,
        value: &Value,
        at: &str,
        errors: &mut Vec<String>,
    ) {
        let (file, key, schema) = self.resolve(base, reference);
        self.validate_schema(&file, Some(&key), &schema, value, at, errors);
    }

    fn validate_schema(
        &self,
        file: &str,
        key: Option<&str>,
        schema: &Value,
        value: &Value,
        at: &str,
        errors: &mut Vec<String>,
    ) {
        if schema == &Value::Bool(true) {
            return;
        }
        if schema == &Value::Bool(false) {
            errors.push(format!("{at}: no value is allowed here"));
            return;
        }
        let Some(object) = schema.as_object() else {
            errors.push(format!(
                "{at}: the schema is neither an object nor a boolean"
            ));
            return;
        };
        for keyword in object.keys() {
            assert!(
                ANNOTATIONS.contains(&keyword.as_str())
                    || ASSERTIONS.contains(&keyword.as_str())
                    || keyword.starts_with("x-"),
                "{file}: the keyword `{keyword}` at {at} is not one this check enforces"
            );
        }
        if let Some(reference) = object.get("$ref").and_then(Value::as_str) {
            assert!(
                object.keys().all(|keyword| keyword == "$ref"
                    || ANNOTATIONS.contains(&keyword.as_str())
                    || keyword.starts_with("x-")),
                "{file}: a `$ref` at {at} has constraining siblings, which this check would skip"
            );
            self.validate(file, reference, value, at, errors);
            return;
        }
        if let Some(types) = object.get("type") {
            let allowed: Vec<&str> = match types {
                Value::String(one) => vec![one.as_str()],
                Value::Array(many) => many.iter().filter_map(Value::as_str).collect(),
                _ => Vec::new(),
            };
            if !allowed.iter().any(|kind| is_a(value, kind)) {
                errors.push(format!("{at}: {value} is not of type {types}"));
                return;
            }
        }
        if let Some(expected) = object.get("const")
            && expected != value
        {
            errors.push(format!("{at}: {value} is not {expected}"));
        }
        if let Some(choices) = object.get("enum").and_then(Value::as_array)
            && !choices.contains(value)
        {
            errors.push(format!("{at}: {value} is not one of {choices:?}"));
        }
        if let Some(number) = value.as_f64() {
            if let Some(minimum) = object.get("minimum").and_then(Value::as_f64)
                && number < minimum
            {
                errors.push(format!("{at}: {value} is below {minimum}"));
            }
            if let Some(maximum) = object.get("maximum").and_then(Value::as_f64)
                && number > maximum
            {
                errors.push(format!("{at}: {value} is above {maximum}"));
            }
        }
        if let Some(text) = value.as_str() {
            let length = text.chars().count() as u64;
            if let Some(minimum) = object.get("minLength").and_then(Value::as_u64)
                && length < minimum
            {
                errors.push(format!("{at}: shorter than {minimum}"));
            }
            if let Some(maximum) = object.get("maxLength").and_then(Value::as_u64)
                && length > maximum
            {
                errors.push(format!("{at}: longer than {maximum}"));
            }
        }
        for (keyword, exactly_one) in [("oneOf", true), ("anyOf", false)] {
            let Some(branches) = object.get(keyword).and_then(Value::as_array) else {
                continue;
            };
            let mut matched = Vec::new();
            for branch in branches {
                let saved = self.seen.borrow().clone();
                let mut branch_errors = Vec::new();
                self.validate_schema(file, None, branch, value, at, &mut branch_errors);
                if branch_errors.is_empty() {
                    matched.push(self.seen.borrow().clone());
                }
                *self.seen.borrow_mut() = saved;
            }
            let fits = if exactly_one {
                matched.len() == 1
            } else {
                !matched.is_empty()
            };
            if fits {
                // Coverage counts what the matching branch saw.
                *self.seen.borrow_mut() = matched.swap_remove(0);
            } else {
                errors.push(format!(
                    "{at}: {} of the `{keyword}` branches match {value}",
                    matched.len()
                ));
            }
        }
        if let Some(items) = value.as_array() {
            let count = items.len() as u64;
            if let Some(minimum) = object.get("minItems").and_then(Value::as_u64)
                && count < minimum
            {
                errors.push(format!("{at}: fewer than {minimum} items"));
            }
            if let Some(maximum) = object.get("maxItems").and_then(Value::as_u64)
                && count > maximum
            {
                errors.push(format!("{at}: more than {maximum} items"));
            }
            if let Some(schema) = object.get("items") {
                for (index, item) in items.iter().enumerate() {
                    self.validate_schema(
                        file,
                        None,
                        schema,
                        item,
                        &format!("{at}[{index}]"),
                        errors,
                    );
                }
            }
        }
        if let Some(members) = value.as_object() {
            let properties = object
                .get("properties")
                .and_then(Value::as_object)
                .cloned()
                .unwrap_or_default();
            if let Some(required) = object.get("required").and_then(Value::as_array) {
                for name in required.iter().filter_map(Value::as_str) {
                    if !members.contains_key(name) {
                        errors.push(format!("{at}: the required member `{name}` is absent"));
                    }
                }
            }
            for (name, member) in members {
                let place = format!("{at}.{name}");
                if let Some(schema) = properties.get(name) {
                    if let Some(key) = key {
                        self.seen
                            .borrow_mut()
                            .entry(key.to_owned())
                            .or_default()
                            .insert(name.clone());
                    }
                    self.validate_schema(file, None, schema, member, &place, errors);
                    continue;
                }
                match object.get("additionalProperties") {
                    Some(Value::Bool(false)) => {
                        errors.push(format!("{place}: a member the schema does not name"));
                    }
                    Some(schema @ Value::Object(_)) => {
                        self.validate_schema(file, None, schema, member, &place, errors);
                    }
                    _ => {}
                }
            }
        }
    }
}

/// Every schema keyword in `document` this check does not enforce, wherever it sits: a constraint
/// on a schema no checked value reaches is still a constraint the document claims.
pub fn unenforced_keywords(document: &Value) -> Vec<String> {
    fn walk(node: &Value, at: &str, schema: bool, into: &mut Vec<String>) {
        match node {
            Value::Object(members) => {
                for (key, member) in members {
                    let place = format!("{at}.{key}");
                    if schema
                        && !(ANNOTATIONS.contains(&key.as_str())
                            || ASSERTIONS.contains(&key.as_str())
                            || key.starts_with("x-"))
                    {
                        into.push(format!("{place}: `{key}`"));
                    }
                    let child_is_schema = schema
                        && matches!(
                            key.as_str(),
                            "items" | "additionalProperties" | "oneOf" | "anyOf"
                        );
                    if schema && key == "properties" {
                        if let Value::Object(properties) = member {
                            for (name, property) in properties {
                                walk(property, &format!("{place}.{name}"), true, into);
                            }
                        }
                        continue;
                    }
                    if !schema && key == "schema" {
                        walk(member, &place, true, into);
                        continue;
                    }
                    if !schema && at == "$.components.schemas" {
                        walk(member, &place, true, into);
                        continue;
                    }
                    walk(member, &place, child_is_schema, into);
                }
            }
            Value::Array(items) => {
                for (index, item) in items.iter().enumerate() {
                    walk(item, &format!("{at}[{index}]"), schema, into);
                }
            }
            _ => {}
        }
    }
    let mut found = Vec::new();
    walk(document, "$", false, &mut found);
    found
}

fn is_a(value: &Value, kind: &str) -> bool {
    match kind {
        "null" => value.is_null(),
        "boolean" => value.is_boolean(),
        "object" => value.is_object(),
        "array" => value.is_array(),
        "string" => value.is_string(),
        "number" => value.is_number(),
        "integer" => value.is_i64() || value.is_u64(),
        _ => false,
    }
}

fn read(path: &Path) -> Value {
    let text = fs::read_to_string(path)
        .unwrap_or_else(|error| panic!("{} cannot be read: {error}", path.display()));
    serde_json::from_str(&text)
        .unwrap_or_else(|error| panic!("{} is not JSON: {error}", path.display()))
}

fn collect_references(value: &Value, into: &mut Vec<String>) {
    match value {
        Value::Object(members) => {
            for (name, member) in members {
                if name == "$ref"
                    && let Some(reference) = member.as_str()
                {
                    into.push(reference.to_owned());
                }
                collect_references(member, into);
            }
        }
        Value::Array(items) => items.iter().for_each(|item| collect_references(item, into)),
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn document(schemas: Value) -> Document {
        let mut documents = BTreeMap::new();
        documents.insert(
            "test.json".to_owned(),
            json!({ "components": { "schemas": schemas } }),
        );
        Document {
            name: "test.json".to_owned(),
            documents,
            seen: RefCell::new(BTreeMap::new()),
        }
    }

    #[test]
    fn test_a_closed_object_refuses_an_unknown_member_and_an_absent_required_one() {
        let doc = document(json!({
            "Thing": {
                "type": "object",
                "required": ["a"],
                "properties": { "a": { "type": "integer" }, "b": { "type": "string" } },
                "additionalProperties": false
            }
        }));
        assert!(doc.accepts_json("Thing", &json!({ "a": 1 })));
        assert!(!doc.accepts_json("Thing", &json!({ "a": 1, "c": true })));
        assert!(!doc.accepts_json("Thing", &json!({ "b": "x" })));
        assert!(!doc.accepts_json("Thing", &json!({ "a": "1" })));
    }

    #[test]
    fn test_coverage_names_a_declared_member_no_value_carried() {
        let doc = document(json!({
            "Thing": {
                "type": "object",
                "properties": { "a": { "type": "integer" }, "b": { "type": "string" } },
                "additionalProperties": false
            }
        }));
        doc.check_json("Thing", &json!({ "a": 1 }));
        let missed =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| doc.assert_covered()));
        assert!(missed.is_err(), "`b` was never seen");
        doc.check_json("Thing", &json!({ "b": "x" }));
        doc.assert_covered();
    }

    #[test]
    fn test_one_of_needs_exactly_one_branch_and_references_resolve() {
        let doc = document(json!({
            "Leaf": { "type": "string", "enum": ["x", "y"] },
            "Either": { "oneOf": [ { "$ref": "#/components/schemas/Leaf" }, { "type": "integer" } ] },
            "Both": { "oneOf": [ { "type": "integer" }, { "type": "number" } ] }
        }));
        assert!(doc.accepts_json("Either", &json!("x")));
        assert!(doc.accepts_json("Either", &json!(3)));
        assert!(!doc.accepts_json("Either", &json!("z")));
        assert!(
            !doc.accepts_json("Both", &json!(3)),
            "an integer is also a number"
        );
    }

    #[test]
    fn test_the_static_check_finds_a_keyword_no_value_reaches() {
        let found = unenforced_keywords(&json!({
            "paths": { "/x": { "get": { "responses": { "200": { "content": {
                "application/json": { "schema": { "type": "string", "pattern": "^a" } } } } } } } },
            "components": { "schemas": {
                "Thing": { "type": "object", "properties": { "a": { "allOf": [] } },
                           "additionalProperties": false }
            } }
        }));
        assert_eq!(found.len(), 2, "{found:?}");
    }

    #[test]
    #[should_panic(expected = "is not one this check enforces")]
    fn test_a_keyword_the_validator_does_not_enforce_is_refused() {
        let doc = document(json!({ "Thing": { "type": "string", "pattern": "^a" } }));
        doc.check_json("Thing", &json!("a"));
    }
}
