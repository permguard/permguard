// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The REST to gRPC field mapping, written in the OpenAPI documents and resolved against the
//! checked-in protos.
//!
//! A surface served on both bindings states its mapping explicitly, so neither binding can grow
//! a member the other lacks unnoticed:
//!
//! | Annotation             | Where             | Meaning                                                       |
//! | ---------------------- | ----------------- | ------------------------------------------------------------- |
//! | `x-grpc-message`       | component schema  | the message it maps to, `package.Message`, or `null`          |
//! | `x-grpc-field`         | property          | the field it maps to, or `null`                               |
//! | `x-grpc-only`          | component schema  | fields of the message with no REST member                     |
//! | `x-grpc-rpc`           | operation         | the method it maps to, `package.Service/Method`, or `null`    |
//! | `x-grpc-field`         | parameter         | the field of the method's input message it maps to, or `null` |
//! | `x-grpc-body`          | operation         | input field to body member, or to `$` for the whole body      |
//! | `x-grpc-only`          | operation         | input fields no parameter or body carries                     |
//! | `x-cbor-request`       | operation         | the `contracts/cbor/notp.json` map its CBOR body is           |
//! | `x-grpc-unmapped`      | document root     | messages no schema names, each with its fields and a `note`   |
//! | `x-grpc-unmapped-rpcs` | document root     | methods no operation names, each with a `note`                |
//! | `x-grpc-note`          | beside any `null` | why there is no counterpart                                   |
//!
//! A CBOR body is mapped in its registry instead: a map names its `grpc_message`, each field its
//! `grpc_field` (or `null` with a `grpc_note`), and `grpc_only` lists the rest.
//!
//! Every component schema, property, operation and parameter of a mapped document is annotated,
//! every name resolves, every field of a mapped message, and of a mapped method's input, is a
//! counterpart of something on the REST side or listed as gRPC-only, and every message a mapped
//! method reaches, through its input or its answer, is named by a schema or a registry map or
//! listed as unmapped with the reason.

use std::collections::{BTreeMap, BTreeSet};

use permguard_conformance::contracts::{descriptors, message_fields};
use permguard_conformance::schema::Document;
use serde_json::{Map, Value};

/// The documents of the surfaces served on both bindings, and the ones described for REST only.
const MAPPED: [&str; 10] = [
    "catalog.json",
    "common.json",
    "discovery.json",
    "evidence-decisions.json",
    "evidence-events-v1alpha1.json",
    "health.json",
    "notp.json",
    "pdp-native-v1.json",
    "pdp-temporal-v1alpha1.json",
    "stream-common.json",
];

const METHODS: [&str; 5] = ["get", "post", "put", "patch", "delete"];

fn note(object: &Map<String, Value>, at: &str, offences: &mut Vec<String>) {
    if !object
        .get("x-grpc-note")
        .and_then(Value::as_str)
        .is_some_and(|note| !note.trim().is_empty())
    {
        offences.push(format!(
            "{at}: no counterpart and no `x-grpc-note` saying why"
        ));
    }
}

/// Every method as `package.Service/Method`, with its input and output messages.
fn signatures(set: &prost_types::FileDescriptorSet) -> BTreeMap<String, (String, String)> {
    set.file
        .iter()
        .flat_map(|file| {
            file.service.iter().flat_map(move |service| {
                service.method.iter().map(move |method| {
                    (
                        format!("{}.{}/{}", file.package(), service.name(), method.name()),
                        (
                            method.input_type().trim_start_matches('.').to_owned(),
                            method.output_type().trim_start_matches('.').to_owned(),
                        ),
                    )
                })
            })
        })
        .collect()
}

/// Every message by its full name, nested ones included.
fn every_message(
    set: &prost_types::FileDescriptorSet,
) -> BTreeMap<String, prost_types::DescriptorProto> {
    fn walk(
        prefix: &str,
        messages: &[prost_types::DescriptorProto],
        into: &mut BTreeMap<String, prost_types::DescriptorProto>,
    ) {
        for message in messages {
            let name = format!("{prefix}.{}", message.name());
            walk(&name, &message.nested_type, into);
            into.insert(name, message.clone());
        }
    }
    let mut found = BTreeMap::new();
    for file in &set.file {
        walk(file.package(), &file.message_type, &mut found);
    }
    found
}

/// The messages `root` reaches through its message-typed fields, itself included; a map field's
/// entry is walked through to its value, and the well-known types are left out.
fn reached(
    messages: &BTreeMap<String, prost_types::DescriptorProto>,
    root: &str,
) -> BTreeSet<String> {
    let mut seen = BTreeSet::new();
    let mut pending = vec![root.to_owned()];
    while let Some(name) = pending.pop() {
        let Some(message) = messages.get(&name) else {
            continue;
        };
        let entry = message
            .options
            .as_ref()
            .is_some_and(|options| options.map_entry());
        if !entry && !seen.insert(name.clone()) {
            continue;
        }
        for field in &message.field {
            let target = field.type_name().trim_start_matches('.');
            if !target.is_empty() && !target.starts_with("google.protobuf.") {
                pending.push(target.to_owned());
            }
        }
    }
    seen
}

/// Every method as `package.Service/Method`, with its input message as `package.Message`.
fn methods(set: &prost_types::FileDescriptorSet) -> BTreeMap<String, String> {
    set.file
        .iter()
        .flat_map(|file| {
            file.service.iter().flat_map(move |service| {
                service.method.iter().map(move |method| {
                    (
                        format!("{}.{}/{}", file.package(), service.name(), method.name()),
                        method.input_type().trim_start_matches('.').to_owned(),
                    )
                })
            })
        })
        .collect()
}

/// The schema `schema` stands for, following one `$ref`.
fn resolve(document: &Document, name: &str, schema: &Value) -> Value {
    let Some(reference) = schema.get("$ref").and_then(Value::as_str) else {
        return schema.clone();
    };
    let (file, pointer) = reference.split_once('#').unwrap_or((reference, ""));
    if file.is_empty() || file == name {
        document
            .value()
            .pointer(pointer)
            .cloned()
            .unwrap_or_default()
    } else {
        Document::load(file)
            .value()
            .pointer(pointer)
            .cloned()
            .unwrap_or_default()
    }
}

/// The component schema a request body names, as `file#/components/schemas/Name`.
fn body_message(document: &Document, name: &str, operation: &Map<String, Value>) -> Option<String> {
    let reference = operation
        .get("requestBody")?
        .get("content")?
        .as_object()?
        .values()
        .next()?
        .get("schema")?
        .get("$ref")?
        .as_str()?;
    let (file, pointer) = reference.split_once('#')?;
    let schema = if file.is_empty() || file == name {
        document.value().pointer(pointer)?.clone()
    } else {
        Document::load(file).value().pointer(pointer)?.clone()
    };
    schema
        .get("x-grpc-message")
        .and_then(Value::as_str)
        .map(str::to_owned)
}

#[test]
fn test_every_mapped_member_and_operation_resolves_against_the_protos_both_ways() {
    let set = descriptors();
    let rpcs = methods(&set);
    let mut offences = Vec::new();
    let cbor_maps = cbor_mappings(&set, &mut offences);
    let mut named: BTreeSet<String> = cbor_maps
        .values()
        .map(|(message, _)| message.clone())
        .collect();
    let mut used = BTreeSet::new();
    let mut unmapped_rpcs = BTreeSet::new();

    for name in MAPPED {
        let document = Document::load(name);
        let value = document.value();
        for unmapped in value
            .get("x-grpc-unmapped")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let message = unmapped["message"].as_str().unwrap_or_default();
            if unmapped["note"]
                .as_str()
                .is_none_or(|note| note.trim().is_empty())
            {
                offences.push(format!("{name}: `{message}` is unmapped without a note"));
            }
            // An unmapped message restates its fields, so a field added to it fails here too.
            let listed: Vec<String> = unmapped["fields"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect();
            match message_fields(&set, message) {
                Some(fields) if fields == listed => {}
                Some(fields) => offences.push(format!(
                    "{name}: unmapped `{message}` lists {listed:?}, the proto has {fields:?}"
                )),
                None => offences.push(format!("{name}: unmapped `{message}` is no message")),
            }
            named.insert(message.to_owned());
        }
        for unmapped in value
            .get("x-grpc-unmapped-rpcs")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let rpc = unmapped["rpc"].as_str().unwrap_or_default();
            if unmapped["note"]
                .as_str()
                .is_none_or(|note| note.trim().is_empty())
            {
                offences.push(format!("{name}: `{rpc}` is unmapped without a note"));
            }
            if !rpcs.contains_key(rpc) {
                offences.push(format!("{name}: unmapped `{rpc}` is no method"));
            }
            unmapped_rpcs.insert(rpc.to_owned());
        }

        let schemas = value["components"]["schemas"]
            .as_object()
            .cloned()
            .unwrap_or_default();
        for (schema_name, schema) in &schemas {
            let at = format!("{name} {schema_name}");
            let Some(schema) = schema.as_object() else {
                continue;
            };
            let message = match schema.get("x-grpc-message") {
                Some(Value::String(message)) => {
                    named.insert(message.clone());
                    message.clone()
                }
                Some(Value::Null) => {
                    note(schema, &at, &mut offences);
                    continue;
                }
                _ => {
                    offences.push(format!("{at}: no `x-grpc-message`"));
                    continue;
                }
            };
            let Some(fields) = message_fields(&set, &message) else {
                offences.push(format!("{at}: `{message}` is no message of the protos"));
                continue;
            };
            let mut mapped = BTreeSet::new();
            let properties = schema
                .get("properties")
                .and_then(Value::as_object)
                .cloned()
                .unwrap_or_default();
            for (property, member) in &properties {
                let place = format!("{at}.{property}");
                let member = member.as_object().cloned().unwrap_or_default();
                match member.get("x-grpc-field") {
                    Some(Value::String(field)) => {
                        if fields.contains(field) {
                            mapped.insert(field.clone());
                        } else {
                            offences.push(format!("{place}: `{message}` has no field `{field}`"));
                        }
                    }
                    Some(Value::Null) => note(&member, &place, &mut offences),
                    _ => offences.push(format!("{place}: no `x-grpc-field`")),
                }
            }
            for only in schema
                .get("x-grpc-only")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
            {
                if !fields.iter().any(|field| field == only) {
                    offences.push(format!("{at}: `x-grpc-only` names `{only}`, not a field"));
                }
                mapped.insert(only.to_owned());
            }
            for field in &fields {
                if !mapped.contains(field) {
                    offences.push(format!(
                        "{at}: `{message}.{field}` is neither a member's counterpart nor gRPC-only"
                    ));
                }
            }
        }

        let paths = value["paths"].as_object().cloned().unwrap_or_default();
        for (path, item) in &paths {
            for method in METHODS {
                let Some(operation) = item.get(method).and_then(Value::as_object) else {
                    continue;
                };
                let at = format!("{name} {method} {path}");
                let input = match operation.get("x-grpc-rpc") {
                    Some(Value::String(rpc)) => match rpcs.get(rpc) {
                        Some(input) => {
                            used.insert(rpc.clone());
                            input.clone()
                        }
                        None => {
                            offences.push(format!("{at}: `{rpc}` is no method of the protos"));
                            continue;
                        }
                    },
                    Some(Value::Null) => {
                        note(operation, &at, &mut offences);
                        continue;
                    }
                    _ => {
                        offences.push(format!("{at}: no `x-grpc-rpc`"));
                        continue;
                    }
                };
                // The method's input is carried by the body schema, when it maps to the same
                // message, or field by field by the parameters, the body members and the CBOR map.
                let body_maps =
                    body_message(&document, name, operation).as_deref() == Some(input.as_str());
                let Some(fields) = message_fields(&set, &input) else {
                    offences.push(format!("{at}: input `{input}` is no message"));
                    continue;
                };
                // Checked field by field below, the input is mapped by this operation.
                named.insert(input.clone());
                let mut carried = BTreeSet::new();
                let parameters = item
                    .get("parameters")
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                    .chain(
                        operation
                            .get("parameters")
                            .and_then(Value::as_array)
                            .into_iter()
                            .flatten(),
                    );
                for parameter in parameters {
                    let Some(parameter) = parameter.as_object() else {
                        continue;
                    };
                    let place = format!(
                        "{at} parameter `{}`",
                        parameter.get("name").and_then(Value::as_str).unwrap_or("?")
                    );
                    match parameter.get("x-grpc-field") {
                        Some(Value::String(field)) if fields.contains(field) => {
                            carried.insert(field.clone());
                        }
                        Some(Value::String(field)) => {
                            offences.push(format!("{place}: `{input}` has no field `{field}`"));
                        }
                        Some(Value::Null) => note(parameter, &place, &mut offences),
                        _ => offences.push(format!("{place}: no `x-grpc-field`")),
                    }
                }
                let body_properties = operation
                    .get("requestBody")
                    .and_then(|body| body.get("content"))
                    .and_then(Value::as_object)
                    .and_then(|content| content.values().next())
                    .and_then(|media| media.get("schema"))
                    .map(|schema| resolve(&document, name, schema))
                    .and_then(|schema| schema.get("properties").cloned())
                    .and_then(|properties| properties.as_object().cloned())
                    .unwrap_or_default();
                for (field, member) in operation
                    .get("x-grpc-body")
                    .and_then(Value::as_object)
                    .into_iter()
                    .flatten()
                {
                    let member = member.as_str().unwrap_or_default();
                    if !fields.contains(field) {
                        offences.push(format!(
                            "{at}: `x-grpc-body` names `{field}`, not an input field"
                        ));
                    } else if member != "$" && !body_properties.contains_key(member) {
                        offences.push(format!(
                            "{at}: `x-grpc-body` names `{member}`, not a body member"
                        ));
                    } else {
                        carried.insert(field.clone());
                    }
                }
                if let Some(map) = operation.get("x-cbor-request").and_then(Value::as_str) {
                    match cbor_maps.get(map) {
                        Some(registered) if registered.0 == input => {
                            carried.extend(registered.1.iter().cloned());
                        }
                        Some(registered) => offences.push(format!(
                            "{at}: CBOR map `{map}` maps `{}`, not the input `{input}`",
                            registered.0
                        )),
                        None => offences.push(format!("{at}: no CBOR map `{map}`")),
                    }
                }
                for only in operation
                    .get("x-grpc-only")
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                    .filter_map(Value::as_str)
                {
                    if !fields.iter().any(|field| field == only) {
                        offences.push(format!("{at}: `x-grpc-only` names `{only}`, not a field"));
                    }
                    carried.insert(only.to_owned());
                }
                if body_maps {
                    continue;
                }
                for field in &fields {
                    if !carried.contains(field) {
                        offences.push(format!(
                            "{at}: input field `{input}.{field}` is carried by nothing on REST and \
                             not listed gRPC-only"
                        ));
                    }
                }
            }
        }
    }

    // Every method the planes serve is named by an operation or listed as unmapped: a gRPC-only
    // method is a mapping decision, never an accident.
    for rpc in rpcs.keys() {
        let served =
            rpc.starts_with("permguard.control.v1.") || rpc.starts_with("permguard.data.v1.");
        if served && !used.contains(rpc) && !unmapped_rpcs.contains(rpc) {
            offences.push(format!(
                "`{rpc}` is named by no operation and not listed in `x-grpc-unmapped-rpcs`"
            ));
        }
    }

    // Closure: every message a mapped method reaches is named somewhere, or listed as unmapped.
    let messages = every_message(&set);
    let signatures = signatures(&set);
    for rpc in used.iter().chain(unmapped_rpcs.iter()) {
        // An unmapped entry that names no method is already an offence; nothing to walk.
        let Some((input, output)) = signatures.get(rpc) else {
            continue;
        };
        for root in [input, output] {
            for message in reached(&messages, root) {
                if !named.contains(&message) {
                    offences.push(format!(
                        "`{message}`, reached from `{rpc}`, is named by no schema or registry map \
                         and not listed in `x-grpc-unmapped`"
                    ));
                }
            }
        }
    }

    offences.sort();
    offences.dedup();
    assert!(offences.is_empty(), "{}", offences.join("\n"));
}

/// The CBOR maps of `contracts/cbor/notp.json` that name a gRPC message, each resolved: map name
/// to the message and the fields its labels carry.
fn cbor_mappings(
    set: &prost_types::FileDescriptorSet,
    offences: &mut Vec<String>,
) -> BTreeMap<String, (String, BTreeSet<String>)> {
    let path = permguard_conformance::contracts::root().join("cbor/notp.json");
    let registry: Value = serde_json::from_str(
        &std::fs::read_to_string(&path).expect("the NOTP registry is checked in"),
    )
    .expect("the NOTP registry is JSON");
    let mut found = BTreeMap::new();
    for (name, map) in registry["maps"].as_object().cloned().unwrap_or_default() {
        let at = format!("cbor/notp.json {name}");
        let message = match map.get("grpc_message") {
            Some(Value::String(message)) => message.clone(),
            Some(Value::Null) => {
                if map["grpc_note"]
                    .as_str()
                    .is_none_or(|note| note.trim().is_empty())
                {
                    offences.push(format!("{at}: no counterpart and no `grpc_note`"));
                }
                continue;
            }
            _ => {
                offences.push(format!("{at}: no `grpc_message`"));
                continue;
            }
        };
        let Some(fields) = message_fields(set, &message) else {
            offences.push(format!("{at}: `{message}` is no message"));
            continue;
        };
        let mut carried = BTreeSet::new();
        for field in map["fields"].as_array().into_iter().flatten() {
            let place = format!("{at}.{}", field["name"].as_str().unwrap_or("?"));
            match field.get("grpc_field") {
                Some(Value::String(grpc)) if fields.contains(grpc) => {
                    carried.insert(grpc.clone());
                }
                Some(Value::String(grpc)) => {
                    offences.push(format!("{place}: `{message}` has no field `{grpc}`"));
                }
                Some(Value::Null) => {
                    if field["grpc_note"]
                        .as_str()
                        .is_none_or(|note| note.trim().is_empty())
                    {
                        offences.push(format!("{place}: no counterpart and no `grpc_note`"));
                    }
                }
                _ => offences.push(format!("{place}: no `grpc_field`")),
            }
        }
        for only in map["grpc_only"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
        {
            if !fields.iter().any(|field| field == only) {
                offences.push(format!("{at}: `grpc_only` names `{only}`, not a field"));
            }
            carried.insert(only.to_owned());
        }
        for field in &fields {
            if !carried.contains(field) {
                offences.push(format!("{at}: `{message}.{field}` is carried by no label"));
            }
        }
        found.insert(name, (message, carried));
    }
    found
}

/// The descriptor set holds every checked-in proto, so a name that does not resolve is a real gap.
#[test]
fn test_the_descriptor_set_holds_every_package() {
    let packages: BTreeSet<String> = descriptors()
        .file
        .iter()
        .map(|file| file.package().to_owned())
        .collect();
    for package in [
        "permguard.control.v1",
        "permguard.data.v1",
        "permguard.host.v1",
    ] {
        assert!(packages.contains(package), "{package}");
    }
}
