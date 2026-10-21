// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! DOGWOOD-08: what a warm Dogwood history is charged is never below what its engine keeps.
//!
//! The warm budget admits and evicts by these charges (DOGWOOD-02), so a charge that undercounts
//! lets a Host hold more than its configured bytes. This binary counts every allocation the
//! process makes, builds one history's engine and feeds it events of several sizes, and requires
//! the bytes the budget was charged to be at least the heap the engine retained.
//!
//! One test, run alone in its binary, because the counter is process-wide.

#![allow(clippy::expect_used, unsafe_code)]

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicIsize, Ordering};

use permguard_languages::artifact::{ArtifactBlob, Artifacts, artifact_type};
use permguard_languages::evaluate::StoredPolicy;
use permguard_languages::temporal::Temporal;
use serde_json::{Value as Json, json};

/// The system allocator, counting the bytes currently allocated.
struct Counting;

static LIVE: AtomicIsize = AtomicIsize::new(0);

// SAFETY: every call is forwarded unchanged to `System`; the counter only observes sizes.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: forwarded with the caller's layout.
        let pointer = unsafe { System.alloc(layout) };
        if !pointer.is_null() {
            LIVE.fetch_add(layout.size() as isize, Ordering::SeqCst);
        }
        pointer
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        // SAFETY: forwarded with the caller's pointer and layout.
        unsafe { System.dealloc(pointer, layout) };
        LIVE.fetch_sub(layout.size() as isize, Ordering::SeqCst);
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        // SAFETY: forwarded with the caller's layout.
        let pointer = unsafe { System.alloc_zeroed(layout) };
        if !pointer.is_null() {
            LIVE.fetch_add(layout.size() as isize, Ordering::SeqCst);
        }
        pointer
    }

    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        // SAFETY: forwarded with the caller's pointer, layout and size.
        let moved = unsafe { System.realloc(pointer, layout, new_size) };
        if !moved.is_null() {
            LIVE.fetch_add(new_size as isize - layout.size() as isize, Ordering::SeqCst);
        }
        moved
    }
}

#[global_allocator]
static COUNTING: Counting = Counting;

const POLICY: &str = include_str!("fixtures/dogwood/read-login-not-logout.dw");
const ACTION_SCHEMA: &str = include_str!("fixtures/dogwood/read-login-not-logout.cedarschema");
const EVENT_SCHEMA: &str = include_str!("fixtures/dogwood/pinned.dwschema");

fn bundle() -> Artifacts {
    let mut artifacts = Artifacts::default();
    for (name, data) in [
        (
            permguard_languages::dogwood_artifacts::ACTION_SCHEMA,
            ACTION_SCHEMA,
        ),
        (
            permguard_languages::dogwood_artifacts::EVENT_SCHEMA,
            EVENT_SCHEMA,
        ),
    ] {
        let held = artifact_type(name).expect("a registered artifact");
        artifacts.insert(
            held,
            ArtifactBlob {
                name: held.canonical_filename().unwrap_or(name).to_owned(),
                media_type: held.media_type().to_owned(),
                data: data.as_bytes().to_vec(),
            },
        );
    }
    artifacts
}

fn login(at: i64, user: &str, server: &str) -> permguard_languages::Occurrence {
    let fields: Json = json!({"input": {"user": user, "server": server}, "output": {}});
    let body: permguard_languages::OccurrenceBody = serde_json::from_value(json!({
        "event_id": format!("login-{user}-{at}"),
        "kind": "response",
        "action": "Drupe::Action::Login",
        "principal": format!("Drupe::OAuthUser::\"{user}\""),
        "resource": "Drupe::Gateway::\"gw1\"",
        "logged": fields,
        "request_context": {"input": fields["input"]},
        "occurred_at": permguard_events::index::render_epoch_seconds(at).expect("an instant"),
    }))
    .expect("the body parses");
    body.read().expect("well formed")
}

/// Feeds `count` events to a fresh history of `user` and returns what the budget was charged and
/// what the heap retained, both over the same span.
fn measured(
    temporal: &dyn Temporal,
    budget: &permguard_languages::warm::Budget,
    user: &str,
    count: i64,
    server: &str,
) -> (i64, isize) {
    let charged_before = budget.held("acme", 1).0 as i64;
    let events: Vec<_> = (0..count).map(|at| login(at, user, server)).collect();
    let checked: Vec<_> = events
        .iter()
        .map(|event| temporal.check(event).expect("well formed"))
        .collect();
    let history = checked[0].pin_values().join("\u{1f}");

    let before = LIVE.load(Ordering::SeqCst);
    for (event, checked) in events.iter().zip(&checked) {
        permguard_languages::headroom::with(|| temporal.apply(&history, event, checked));
    }
    let after = LIVE.load(Ordering::SeqCst);

    (
        budget.held("acme", 1).0 as i64 - charged_before,
        after - before,
    )
}

#[test]
fn test_a_warm_history_is_charged_at_least_what_its_engine_retains() {
    let engine = permguard_languages::registry::evaluating("dogwood").expect("dogwood");
    let compiled = permguard_languages::headroom::with(|| {
        engine.compile(
            &[StoredPolicy {
                id: "01a0-read".to_owned(),
                alias: None,
                source: POLICY.as_bytes().to_vec(),
            }],
            &bundle(),
        )
    })
    .expect("the example compiles");
    let temporal = compiled.temporal().expect("it remembers");
    let budget = permguard_languages::warm::Budget::new(permguard_languages::warm::Limits {
        host: u64::MAX,
        zone: u64::MAX,
        partition: u64::MAX,
    });
    temporal.bind_warm(&budget, "acme");

    // Whatever the engine builds once per process is not charged to a history.
    measured(temporal, &budget, "warm-up", 50, "s1");

    let large = "x".repeat(4096);
    let mut results = Vec::new();
    for (user, count, server) in [
        ("one", 1, "s1"),
        ("hundred", 100, "s1"),
        ("thousand", 1000, "s1"),
        ("wide", 100, large.as_str()),
    ] {
        let (charged, retained) = measured(temporal, &budget, user, count, server);
        println!("{user} x{count}: charged {charged}, retained {retained}");
        results.push((user, charged, retained));
    }
    for (user, charged, retained) in results {
        assert!(
            charged >= retained as i64,
            "`{user}`: charged {charged} bytes and the engine retained {retained}"
        );
    }
}
