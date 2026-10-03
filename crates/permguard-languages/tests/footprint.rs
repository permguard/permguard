// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! LANG-07: a compiled partition's footprint is never below what its engine actually keeps.
//!
//! The cache admits and evicts by footprint, so a footprint that undercounts lets a plane hold far
//! more than its configured bytes. This binary counts every allocation the process makes, compiles
//! a range of partitions for each runtime, and requires each evaluator's reported footprint to be
//! at least the heap it retains — the bytes still allocated once the compile has returned and its
//! temporaries are gone.
//!
//! One test, run alone in its binary, because the counter is process-wide.

#![allow(clippy::expect_used, unsafe_code)]

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicIsize, Ordering};

use permguard_languages::artifact::{ArtifactBlob, Artifacts, artifact_type};
use permguard_languages::evaluate::{Evaluator, StoredPolicy};

/// The system allocator, counting the bytes currently allocated.
struct Counting;

static LIVE: AtomicIsize = AtomicIsize::new(0);

// SAFETY: every call is forwarded unchanged to `System`; the counter only observes sizes.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: forwarded with the caller's layout.
        let pointer = unsafe { System.alloc(layout) };
        if !pointer.is_null() {
            LIVE.fetch_add(layout.size() as isize, Ordering::Relaxed);
        }
        pointer
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        // SAFETY: forwarded with the pointer and layout the caller allocated with.
        unsafe { System.dealloc(pointer, layout) };
        LIVE.fetch_sub(layout.size() as isize, Ordering::Relaxed);
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        // SAFETY: forwarded with the caller's layout.
        let pointer = unsafe { System.alloc_zeroed(layout) };
        if !pointer.is_null() {
            LIVE.fetch_add(layout.size() as isize, Ordering::Relaxed);
        }
        pointer
    }

    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        // SAFETY: forwarded with the pointer, layout and size the caller passed.
        let moved = unsafe { System.realloc(pointer, layout, new_size) };
        if !moved.is_null() {
            LIVE.fetch_add(
                new_size as isize - layout.size() as isize,
                Ordering::Relaxed,
            );
        }
        moved
    }
}

#[global_allocator]
static ALLOCATOR: Counting = Counting;

fn policy(id: &str, source: String) -> StoredPolicy {
    StoredPolicy {
        id: id.to_owned(),
        alias: None,
        source: source.into_bytes(),
    }
}

fn artifacts(held: &[(&str, &[u8])]) -> Artifacts {
    let mut artifacts = Artifacts::default();
    for (name, data) in held {
        let artifact = artifact_type(name).expect("a registered artifact");
        artifacts.insert(
            artifact,
            ArtifactBlob {
                name: artifact
                    .canonical_filename()
                    .unwrap_or(artifact.semantic_role())
                    .to_owned(),
                media_type: artifact.media_type().to_owned(),
                data: data.to_vec(),
            },
        );
    }
    artifacts
}

/// Compiles, and returns the evaluator with the heap it retained.
///
/// `warm` is compiled first and dropped: whatever the engine builds once per process is not charged
/// to the partition. It is *different* content from what is measured, so a cache that grows with
/// what it compiles — interned names, compiled patterns — is charged to the partition that grew it.
fn retained(
    language: &str,
    warm: (&[StoredPolicy], &Artifacts),
    policies: &[StoredPolicy],
    held: &Artifacts,
) -> (Box<dyn Evaluator>, isize) {
    let engine =
        permguard_languages::registry::evaluating(language).expect("an evaluating runtime");
    drop(engine.compile(warm.0, warm.1));
    let before = LIVE.load(Ordering::SeqCst);
    let evaluator = permguard_languages::headroom::with(|| engine.compile(policies, held))
        .expect("the partition compiles");
    let after = LIVE.load(Ordering::SeqCst);

    (evaluator, after - before)
}

fn cedar_corpus(prefix: &str, count: usize) -> (Vec<StoredPolicy>, Vec<u8>) {
    let mut schema = String::from(
        "entity User = { department: String, level: Long };\nentity Document = { owner: User, classification: String };\n",
    );
    let mut policies = Vec::new();
    for index in 0..count {
        schema.push_str(&format!(
            "action \"{prefix}{index}\" appliesTo {{ principal: [User], resource: [Document] }};\n"
        ));
        policies.push(policy(
            &format!("cedar-{index}"),
            format!(
                "permit (principal, action == Action::\"{prefix}{index}\", resource)\n  when {{ principal.department == \"dept{index}\" && principal.level > {index} && resource.classification != \"secret-{index}\" }};\n"
            ),
        ));
    }
    (policies, schema.into_bytes())
}

fn rego_corpus(prefix: &str, count: usize) -> Vec<StoredPolicy> {
    (0..count)
        .map(|index| {
            policy(
                &format!("rego-{index}"),
                format!(
                    "package {prefix}{index}\n\nimport rego.v1\n\ndefault allow := false\n\nallow if {{\n    input.subject.id != \"\"\n    input.action.name == \"{prefix}{index}\"\n    some item in input.resource.properties.tags\n    startswith(item, \"tag-{index}\")\n}}\n\ndeny if input.subject.properties.level < {index}\n"
                ),
            )
        })
        .collect()
}

#[test]
fn test_every_runtimes_footprint_is_at_least_what_its_engine_retains() {
    let mut measured = Vec::new();
    let none = Artifacts::default();

    let (warm_cedar, warm_schema) = cedar_corpus("warm", 5);
    let warm_cedar_held = artifacts(&[(
        permguard_core::domains::artifact::CEDAR_SCHEMA_V1,
        &warm_schema,
    )]);
    for count in [1, 10, 100] {
        let (policies, schema) = cedar_corpus("act", count);
        let held = artifacts(&[(permguard_core::domains::artifact::CEDAR_SCHEMA_V1, &schema)]);
        let (evaluator, kept) =
            retained("cedar", (&warm_cedar, &warm_cedar_held), &policies, &held);
        measured.push(("cedar", count, evaluator.footprint(), kept));
    }
    // Schema-heavy: one policy against many entity types, each with many attributes.
    {
        let mut schema = String::new();
        for kind in 0..200 {
            schema.push_str(&format!("entity Kind{kind} = {{"));
            for attribute in 0..10 {
                schema.push_str(&format!(" a{attribute}: String,"));
            }
            schema.push_str(" };\n");
        }
        schema.push_str("action \"read\" appliesTo { principal: [Kind0], resource: [Kind1] };\n");
        let policies = vec![policy(
            "cedar-wide",
            "permit (principal, action == Action::\"read\", resource) when { principal.a0 == resource.a1 };\n"
                .to_owned(),
        )];
        let held = artifacts(&[(
            permguard_core::domains::artifact::CEDAR_SCHEMA_V1,
            schema.as_bytes(),
        )]);
        let (evaluator, kept) =
            retained("cedar", (&warm_cedar, &warm_cedar_held), &policies, &held);
        measured.push(("cedar-schema", 1, evaluator.footprint(), kept));
    }

    let warm_rego = rego_corpus("warm", 5);
    for count in [1, 10, 100] {
        let policies = rego_corpus("p", count);
        let (evaluator, kept) = retained("rego", (&warm_rego, &none), &policies, &none);
        measured.push(("rego", count, evaluator.footprint(), kept));
    }
    // A Rego partition with a JSON Schema for its document, its patterns all its own.
    {
        let mut properties = String::new();
        for field in 0..200 {
            properties.push_str(&format!(
                "\"f{field}\": {{\"type\": \"string\", \"maxLength\": 64, \"pattern\": \"^[a-z]+{field}$\"}},"
            ));
        }
        let schema = format!(
            "{{\"type\": \"object\", \"properties\": {{{}}}, \"additionalProperties\": false}}",
            properties.trim_end_matches(',')
        );
        let policies = rego_corpus("s", 10);
        let held = artifacts(&[(
            permguard_core::domains::artifact::REGO_SCHEMA_V1,
            schema.as_bytes(),
        )]);
        let (evaluator, kept) = retained("rego", (&warm_rego, &none), &policies, &held);
        measured.push(("rego-schema", 10, evaluator.footprint(), kept));
    }

    let example = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../examples/dogwood-session-access/governance"
    );
    let read =
        |file: &str| std::fs::read(format!("{example}/{file}")).expect("the example is readable");
    let template = String::from_utf8(read("read-after-login.dw")).expect("UTF-8");
    // Distinct rules: each its own id and its own window, so nothing is shared between them.
    let dogwood_corpus = |prefix: &str, count: usize| -> Vec<StoredPolicy> {
        (0..count)
            .map(|index| {
                policy(
                    &format!("dogwood-{prefix}-{index}"),
                    template
                        .replace("read_after_login", &format!("{prefix}_{index}"))
                        .replace("within 1h", &format!("within {}m", index + 1)),
                )
            })
            .collect()
    };
    let held = artifacts(&[
        (
            permguard_languages::dogwood_artifacts::ACTION_SCHEMA,
            &read("schema.cedarschema"),
        ),
        (
            permguard_languages::dogwood_artifacts::EVENT_SCHEMA,
            &read("events.dwschema"),
        ),
    ]);
    let warm_dogwood = dogwood_corpus("warm", 2);
    for count in [1, 10, 50] {
        let policies = dogwood_corpus("rule", count);
        let (evaluator, kept) = retained("dogwood", (&warm_dogwood, &held), &policies, &held);
        measured.push(("dogwood", count, evaluator.footprint(), kept));
    }

    for (language, count, footprint, kept) in &measured {
        println!("{language} x{count}: footprint {footprint}, retained {kept}");
    }
    for (language, count, footprint, kept) in measured {
        assert!(
            footprint as isize >= kept,
            "`{language}` with {count} policies reports {footprint} bytes and retains {kept}"
        );
    }
}
