// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The runner for test binaries built without the test harness, because each is its own
//! supervised worker: enough of libtest's command line for `cargo test` and `cargo nextest`.

use std::process::ExitCode;

/// One case: it returns whether it ran, or `false` when the platform cannot run it.
pub type Case = fn() -> bool;

/// Runs the selected cases and reports them as libtest does.
pub fn run(cases: &[(&str, Case)]) -> ExitCode {
    // Enough of libtest's command line for `cargo test` and `cargo nextest`: `--list` names
    // the cases (none is ignored), and the other free arguments filter them, exactly with
    // `--exact`.
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    if arguments.iter().any(|argument| argument == "--list") {
        if !arguments.iter().any(|argument| argument == "--ignored") {
            for (name, _) in cases {
                println!("{name}: test");
            }
        }
        return ExitCode::SUCCESS;
    }
    // Options that take a value consume it rather than reading as filters.
    const VALUED: &[&str] = &[
        "--test-threads",
        "--format",
        "--color",
        "--logfile",
        "--report-time",
        "-Z",
    ];
    let exact = arguments.iter().any(|argument| argument == "--exact");
    // No case is ignored, so asking for the ignored ones runs none.
    let only_ignored = arguments.iter().any(|argument| argument == "--ignored");
    let mut filters: Vec<&str> = Vec::new();
    let mut skips: Vec<&str> = Vec::new();
    let mut held = arguments.iter();
    while let Some(argument) = held.next() {
        if argument == "--skip" {
            skips.extend(held.next().map(String::as_str));
        } else if VALUED.contains(&argument.as_str()) {
            held.next();
        } else if !argument.starts_with('-') {
            filters.push(argument);
        }
    }
    let matches = |name: &str, filter: &str| {
        if exact {
            name == filter
        } else {
            name.contains(filter)
        }
    };
    let selected = |name: &str| {
        !only_ignored
            && (filters.is_empty() || filters.iter().any(|filter| matches(name, filter)))
            && !skips.iter().any(|skip| matches(name, skip))
    };

    let (mut passed, mut failed, mut ignored) = (0, 0, 0);
    for (name, case) in cases {
        if !selected(name) {
            continue;
        }
        match std::panic::catch_unwind(case) {
            Ok(true) => {
                println!("test {name} ... ok");
                passed += 1;
            }
            Ok(false) => {
                println!("test {name} ... ignored");
                ignored += 1;
            }
            Err(_) => {
                println!("test {name} ... FAILED");
                failed += 1;
            }
        }
    }
    println!(
        "\ntest result: {}. {passed} passed; {failed} failed; {ignored} ignored",
        if failed == 0 { "ok" } else { "FAILED" },
    );

    if failed == 0 {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}
