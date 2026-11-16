// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The fixed reference application of a profile (`11-refactoring/1-dependencies.md`, Resource
//! budgets): it embeds the Data Plane with the languages this build selected, loads one ledger,
//! decides, and reports what the process holds, one `name<TAB>value` line each.
//!
//! | Line            | What it measures                                                 |
//! | --------------- | ---------------------------------------------------------------- |
//! | `started`       | whether the Plane started; a build with no language says why not |
//! | `rss_idle_kb`   | resident memory once started, before any ledger is loaded        |
//! | `decisions`     | the cases of the example decided, each as its case says          |
//! | `rss_loaded_kb` | resident memory after the ledger is loaded and its cases decided |
//! | `threads`       | the threads of the process after deciding                        |
//! | `shutdown_ms`   | how long the ordered shutdown took                               |
//!
//! `--one-worker` runs it under the one-worker profile: one evaluation at a time, none waiting,
//! one piece of blocking work, on a single-threaded runtime. The numbers are trend signals, read
//! by `scripts/measure-embedded-fixture.sh`; nothing here is a gate.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::print_stdout)]

use std::sync::Arc;
use std::time::{Duration, Instant};

use permguard_core::authz::Actor;
use permguard_core::config::{
    SETTING_EVALUATION_CONCURRENCY, SETTING_EVALUATION_QUEUE, SETTING_MAX_BLOCKING,
};
use permguard_embedded_fixture::embed;

#[allow(dead_code)]
#[path = "../../../crates/permguard-data-plane/tests/support/embedded.rs"]
mod composed;
#[allow(dead_code)]
#[path = "../../../crates/permguard-data-plane/tests/support/examples.rs"]
mod examples;

use composed::{Recording, capabilities, config, scratch};

/// The ledger this profile loads, and the requests of the example it answers by itself.
fn ledger() -> Option<(
    permguard_objects::manifest::Manifest,
    &'static [&'static str],
)> {
    let cedar = cfg!(feature = "cedar");
    let rego = cfg!(feature = "rego");
    match (cedar, rego) {
        (true, true) => Some((examples::manifest("basics"), &[])),
        (true, false) => Some((
            examples::manifest_narrowed_to("basics", "cedar"),
            &["permit.json", "deny.json"],
        )),
        (false, true) => Some((
            examples::manifest_narrowed_to("basics", "rego"),
            &["gateway-permit.json", "boxcarred.json"],
        )),
        (false, false) => None,
    }
}

/// The resident memory of this process, in kilobytes, as `ps` reports it.
fn resident_kb() -> u64 {
    let output = std::process::Command::new("ps")
        .args(["-o", "rss=", "-p", &std::process::id().to_string()])
        .output()
        .expect("ps runs");
    String::from_utf8_lossy(&output.stdout)
        .trim()
        .parse()
        .unwrap_or(0)
}

/// The threads of this process.
fn threads() -> u64 {
    if let Ok(status) = std::fs::read_to_string("/proc/self/status") {
        return status
            .lines()
            .find_map(|line| line.strip_prefix("Threads:"))
            .and_then(|count| count.trim().parse().ok())
            .unwrap_or(0);
    }
    // Where there is no `/proc`: one line per thread, after the header.
    let output = std::process::Command::new("ps")
        .args(["-M", "-p", &std::process::id().to_string()])
        .output()
        .expect("ps runs");
    (String::from_utf8_lossy(&output.stdout).lines().count() as u64).saturating_sub(1)
}

async fn run(one_worker: bool) {
    let working = scratch("reference");
    let bounds: &[(&str, &str)] = if one_worker {
        &[
            (SETTING_EVALUATION_CONCURRENCY, "1"),
            (SETTING_EVALUATION_QUEUE, "1"),
            (SETTING_MAX_BLOCKING, "1"),
        ]
    } else {
        &[]
    };
    let config = config(&working, bounds);
    let mirrors = config.mirrors_directory();

    let runtime = match embed(capabilities(config, Arc::new(Recording::default()))).await {
        Ok(runtime) => runtime,
        Err(refused) => {
            println!("started\tno: {refused}");
            return;
        }
    };
    println!("started\tyes");
    println!("rss_idle_kb\t{}", resident_kb());

    let mut decided = 0;
    if let Some((manifest, requests)) = ledger() {
        examples::provision_manifest(
            &mirrors,
            "basics",
            manifest,
            "01a1a166-5743-7014-b7bf-197ed0437363",
            "01a1a166-5747-7d8c-a96a-6e17f5281a37",
        );
        for (name, case) in examples::cases("basics") {
            let Some(wanted) = case.expect.decision.as_deref() else {
                continue;
            };
            let asked = std::path::Path::new(&case.request)
                .file_name()
                .and_then(std::ffi::OsStr::to_str)
                .is_some_and(|request| requests.is_empty() || requests.contains(&request));
            if !asked || (!requests.is_empty() && case.profile.is_some()) {
                continue;
            }
            let answer = runtime
                .evaluate(&Actor::Anonymous, examples::request(&name, &case), None)
                .await
                .unwrap_or_else(|refused| panic!("{name}/{}: refused: {refused:?}", case.name));
            assert_eq!(answer.decision, wanted == "permit", "{name}/{}", case.name);
            decided += 1;
        }
    }
    println!("decisions\t{decided}");
    println!("rss_loaded_kb\t{}", resident_kb());
    println!("threads\t{}", threads());

    let asked = Instant::now();
    let shutdown = runtime.shutdown(Duration::from_secs(10)).await;
    assert!(shutdown.unfinished.is_empty(), "{:?}", shutdown.unfinished);
    println!("shutdown_ms\t{}", asked.elapsed().as_millis());
}

fn main() {
    let one_worker = std::env::args().any(|argument| argument == "--one-worker");
    let mut builder = if one_worker {
        tokio::runtime::Builder::new_current_thread()
    } else {
        tokio::runtime::Builder::new_multi_thread()
    };
    builder
        .enable_all()
        .build()
        .expect("the application's runtime")
        .block_on(run(one_worker));
}
