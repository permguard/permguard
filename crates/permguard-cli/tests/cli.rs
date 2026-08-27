// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The CLI, run as the binary people run — offline.
//!
//! Everything here is hermetic: a fresh scratch directory per test, no
//! network, no server. What is asserted is the *interface*: exit statuses
//! (they are documented, scripts depend on them), the three output formats,
//! the failure sentences, and the guards — the lock, the layout gate.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "permguard-cli-test-{name}-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("the scratch directory is created");
    dir
}

fn run(workdir: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_permguard"))
        .arg("-w")
        .arg(workdir)
        .args(args)
        // Hermetic: no operator configuration, no environment surprises.
        .env("PERMGUARD_CONFIG", workdir.join("cli-config.yml"))
        .env_remove("PERMGUARD_TLS_CA_FILE")
        .env("NO_COLOR", "1")
        .output()
        .expect("the binary runs")
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

/// A small authorable workspace: one Cedar partition, two policies.
fn write_sources(dir: &Path) {
    std::fs::write(
        dir.join("manifest.yml"),
        concat!(
            "metadata:\n  kind: policy\n  name: cli-test\n",
            "runtimes:\n  cedar:\n    language: { name: cedar, constraint: \">=4.0.0\" }\n",
            "    engine: { name: permguard, constraint: \">=0.1.0\" }\n",
            "partitions:\n  app: { runtime: cedar, schema: false }\n",
            "profiles:\n  default: { type: permguard.pdp.v1, partitions: [app] }\n",
        ),
    )
    .expect("the manifest writes");
    std::fs::create_dir_all(dir.join("app")).expect("the partition exists");
    std::fs::write(
        dir.join("app/rules.cedar"),
        "@alias(\"readers\")\npermit(principal, action == Action::\"read\", resource);\n\
         @alias(\"writers\")\npermit(principal, action == Action::\"write\", resource);\n",
    )
    .expect("the policy writes");
}

// ---- identity and configuration ------------------------------------------------------------

#[test]
fn version_answers_in_all_three_formats() {
    let dir = scratch("version");

    let terminal = run(&dir, &["version"]);
    assert!(terminal.status.success());
    assert!(stdout(&terminal).contains(env!("CARGO_PKG_VERSION")));

    let json = run(&dir, &["-o", "json", "version"]);
    let parsed: serde_json::Value =
        serde_json::from_str(&stdout(&json)).expect("the JSON output parses");
    assert_eq!(parsed["version"], env!("CARGO_PKG_VERSION"));

    let yaml = run(&dir, &["-o", "yaml", "version"]);
    assert!(stdout(&yaml).contains("version:"));
}

/// `--version`, `-V` and `version` are one question. A flag that grew its own answer would be a
/// second version report to keep in step with the first, which is how the two drift apart.
#[test]
fn the_version_flag_answers_exactly_as_the_version_command_does() {
    let dir = scratch("version-flag");

    for format in ["terminal", "json", "yaml"] {
        let command = run(&dir, &["-o", format, "version"]);
        let long = run(&dir, &["-o", format, "--version"]);
        let short = run(&dir, &["-o", format, "-V"]);

        assert!(command.status.success());
        assert_eq!(stdout(&long), stdout(&command), "-o {format}");
        assert_eq!(stdout(&short), stdout(&command), "-o {format}");
    }
}

#[test]
fn completion_prints_a_shell_script() {
    let dir = scratch("completion");
    let output = run(&dir, &["completion", "zsh"]);

    assert!(output.status.success());
    assert!(stdout(&output).contains("permguard"));
}

#[test]
fn config_set_get_show_reset_round_trip() {
    let dir = scratch("config");

    let set = run(
        &dir,
        &[
            "config",
            "set",
            "control-plane.endpoint",
            "http://10.0.0.9:7556",
        ],
    );
    assert!(set.status.success(), "{}", stderr(&set));

    let get = run(&dir, &["config", "get", "control-plane.endpoint"]);
    assert_eq!(stdout(&get).trim(), "http://10.0.0.9:7556");

    let show = run(&dir, &["-o", "json", "config", "show"]);
    assert!(stdout(&show).contains("10.0.0.9"), "{}", stdout(&show));

    let reset = run(&dir, &["config", "reset", "control-plane.endpoint"]);
    assert!(reset.status.success(), "{}", stderr(&reset));
    let get = run(&dir, &["config", "get", "control-plane.endpoint"]);
    assert!(stdout(&get).contains("127.0.0.1:7556"), "{}", stdout(&get));
}

#[test]
fn an_unknown_setting_is_a_usage_error() {
    let dir = scratch("config-unknown");
    let output = run(&dir, &["config", "get", "no.such.setting"]);

    assert_eq!(output.status.code(), Some(64), "{}", stderr(&output));
}

// ---- the workspace, offline -----------------------------------------------------------------

#[test]
fn init_validate_plan_and_status_work_offline() {
    let dir = scratch("workspace");
    write_sources(&dir);

    let init = run(&dir, &["init", "cli-test"]);
    assert!(init.status.success(), "{}", stderr(&init));
    assert!(dir.join(".permguard/config").exists());

    let validate = run(&dir, &["validate"]);
    assert!(validate.status.success(), "{}", stderr(&validate));
    assert!(stdout(&validate).contains("Valid"), "{}", stdout(&validate));

    let plan = run(&dir, &["-o", "json", "plan"]);
    assert!(plan.status.success(), "{}", stderr(&plan));
    let parsed: serde_json::Value = serde_json::from_str(&stdout(&plan)).expect("plan JSON");
    assert_eq!(parsed["changes"].as_array().expect("changes").len(), 2);

    let status = run(&dir, &["-o", "yaml", "status"]);
    assert!(status.status.success(), "{}", stderr(&status));
    let text = stdout(&status);
    assert!(text.contains("pending_create: 2"), "{text}");
    assert!(text.contains("workspace: cli-test"), "{text}");
}

#[test]
fn a_directory_without_a_workspace_refuses_with_the_way_in() {
    let dir = scratch("no-workspace");
    let output = run(&dir, &["status"]);

    assert_eq!(output.status.code(), Some(64));
    assert!(
        stderr(&output).contains("permguard init"),
        "{}",
        stderr(&output)
    );
}

#[test]
fn an_unsupported_language_at_init_is_refused_naming_the_built_ins() {
    let dir = scratch("bad-language");
    let output = run(&dir, &["init", "x", "--language", "cobol"]);

    assert_eq!(output.status.code(), Some(64));
    assert!(stderr(&output).contains("cedar"), "{}", stderr(&output));
}

#[test]
fn a_duplicate_alias_is_refused_naming_both_declarations() {
    let dir = scratch("dup-alias");
    write_sources(&dir);
    std::fs::write(
        dir.join("app/other.cedar"),
        "@alias(\"readers\")\npermit(principal, action == Action::\"list\", resource);\n",
    )
    .expect("the second policy writes");

    assert!(run(&dir, &["init", "cli-test"]).status.success());
    let output = run(&dir, &["validate"]);

    assert_eq!(output.status.code(), Some(64));
    let text = stderr(&output);
    assert!(text.contains("readers"), "{text}");
}

// ---- the guards ------------------------------------------------------------------------------

#[test]
fn a_held_lock_refuses_the_second_command_and_names_the_holder() {
    let dir = scratch("lock");
    write_sources(&dir);
    assert!(run(&dir, &["init", "cli-test"]).status.success());

    std::fs::write(dir.join(".permguard/lock"), "pid 424242").expect("the lock writes");
    let output = run(&dir, &["plan"]);

    assert_eq!(output.status.code(), Some(64));
    let text = stderr(&output);
    assert!(text.contains("pid 424242"), "{text}");
    assert!(text.contains(".permguard/lock"), "{text}");

    // Read-only commands never take the lock.
    let history = run(&dir, &["history"]);
    assert!(history.status.success(), "{}", stderr(&history));
}

#[test]
fn a_workspace_written_by_another_layout_is_refused_with_the_way_out() {
    let dir = scratch("layout-gate");
    write_sources(&dir);
    assert!(run(&dir, &["init", "cli-test"]).status.success());

    let config = dir.join(".permguard/config");
    let text = std::fs::read_to_string(&config).expect("the config reads");
    std::fs::write(&config, text.replace("version = 2", "version = 1")).expect("rewrites");

    let output = run(&dir, &["status"]);
    assert_eq!(output.status.code(), Some(64));
    let text = stderr(&output);
    assert!(text.contains("layout v1"), "{text}");
    assert!(text.contains("re-clone"), "{text}");
}

// ---- objects ---------------------------------------------------------------------------------

#[test]
fn objects_list_and_every_cat_view_answer() {
    let dir = scratch("objects");
    write_sources(&dir);
    assert!(run(&dir, &["init", "cli-test"]).status.success());
    assert!(run(&dir, &["refresh"]).status.success());

    let list = run(&dir, &["-o", "json", "objects", "list"]);
    assert!(list.status.success(), "{}", stderr(&list));
    let parsed: serde_json::Value = serde_json::from_str(&stdout(&list)).expect("list JSON");
    let objects = parsed["objects"].as_array().expect("objects");
    assert!(!objects.is_empty());
    // Nothing is tracked yet: everything staged, nothing from a remote head.
    assert!(
        objects
            .iter()
            .all(|o| o["staged"] == true && o["tracked"] == false)
    );

    let blob = objects
        .iter()
        .find(|o| o["kind"] == "blob")
        .expect("a blob exists")["digest"]
        .as_str()
        .expect("a digest")
        .to_owned();
    let tree = objects
        .iter()
        .find(|o| o["kind"] == "tree")
        .expect("a tree exists")["digest"]
        .as_str()
        .expect("a digest")
        .to_owned();

    // Default for a blob: its content, pipeable.
    let content = run(&dir, &["objects", "cat", &blob]);
    assert!(content.status.success());

    // Raw: the canonical CBOR bytes, whatever the kind.
    let raw = run(&dir, &["objects", "cat", &blob, "--raw"]);
    assert!(raw.status.success());
    assert!(!raw.stdout.is_empty());

    // Inspect: typed, and structured under -o json.
    let inspect = run(&dir, &["-o", "json", "objects", "cat", &tree, "--inspect"]);
    let parsed: serde_json::Value = serde_json::from_str(&stdout(&inspect)).expect("inspect JSON");
    assert_eq!(parsed["kind"], "tree");
    assert!(!parsed["entries"].as_array().expect("entries").is_empty());

    // Human: a reading, not an error, for every kind.
    let human = run(&dir, &["objects", "cat", &tree, "--human"]);
    assert!(human.status.success());
    assert!(stdout(&human).contains("tree"), "{}", stdout(&human));

    // Content on a non-blob: refused, pointing at the right views.
    let wrong = run(&dir, &["objects", "cat", &tree, "--content"]);
    assert_eq!(wrong.status.code(), Some(64));
    assert!(stderr(&wrong).contains("--inspect"), "{}", stderr(&wrong));

    // A digest nothing answers to.
    let missing = run(
        &dir,
        &[
            "objects",
            "cat",
            "sha256:00000000000000000000000000000000000000000000000000\
           00000000000000",
        ],
    );
    assert_eq!(missing.status.code(), Some(64));
}

// ---- reaching servers, refused cleanly --------------------------------------------------------

#[test]
fn an_unreachable_server_is_an_error_not_a_hang_or_a_panic() {
    let dir = scratch("unreachable");
    write_sources(&dir);
    assert!(run(&dir, &["init", "cli-test"]).status.success());

    // Nothing listens on this port; the refusal must be clean on both transports.
    let http = run(&dir, &["remote", "add", "origin", "http://127.0.0.1:1"]);
    assert_eq!(http.status.code(), Some(64), "{}", stderr(&http));
    assert!(!stderr(&http).contains("panicked"));

    let grpc = run(&dir, &["remote", "add", "origin", "grpc://127.0.0.1:1"]);
    assert_eq!(grpc.status.code(), Some(64), "{}", stderr(&grpc));
    assert!(!stderr(&grpc).contains("panicked"));
}

#[test]
fn skip_verify_over_grpcs_is_refused_with_the_alternative() {
    let dir = scratch("grpcs-skip");
    let output = run(
        &dir,
        &[
            "--tls-skip-verify",
            "--endpoint",
            "grpcs://127.0.0.1:1",
            "zones",
            "list",
        ],
    );

    assert_eq!(output.status.code(), Some(64));
    assert!(
        stderr(&output).contains("--tls-ca-file"),
        "{}",
        stderr(&output)
    );
}

#[test]
fn a_malformed_endpoint_names_whats_wrong() {
    let dir = scratch("bad-endpoint");
    let output = run(&dir, &["--endpoint", "127.0.0.1:7556", "zones", "list"]);

    assert_eq!(output.status.code(), Some(64));
    assert!(stderr(&output).contains("http://"), "{}", stderr(&output));
}

#[test]
fn reading_decisions_without_a_scope_says_which_three_ways_there_are() {
    let dir = scratch("decisions-scope");
    let output = run(
        &dir,
        &[
            "decisions",
            "list",
            "--control-endpoint",
            "http://127.0.0.1:1",
        ],
    );

    assert_eq!(output.status.code(), Some(64));
    let said = stderr(&output);
    for hint in ["--zone", "workspace", "--pdp"] {
        assert!(said.contains(hint), "{said}");
    }
}

#[test]
fn a_decision_log_that_cannot_be_reached_is_unavailable_not_a_usage_error() {
    let dir = scratch("decisions-down");
    let output = run(
        &dir,
        &[
            "decisions",
            "list",
            "--zone",
            "acme",
            "--ledger",
            "main-ledger",
            "--control-endpoint",
            "http://127.0.0.1:1",
            "-o",
            "json",
        ],
    );

    // The distinction a script depends on: nothing the operator typed is
    // wrong, so retrying later is the right response.
    assert_eq!(output.status.code(), Some(70));
    assert!(
        stderr(&output).contains("decision_log_unreachable"),
        "{}",
        stderr(&output)
    );
}

#[test]
fn verify_asks_for_the_producers_keys_rather_than_pretending() {
    let dir = scratch("decisions-keys");
    let output = run(
        &dir,
        &[
            "decisions",
            "list",
            "--zone",
            "acme",
            "--ledger",
            "main-ledger",
            "--control-endpoint",
            "http://127.0.0.1:1",
            "--verify",
            "--keys",
            "no-such-file.json",
        ],
    );

    assert_eq!(output.status.code(), Some(64));
    assert!(
        stderr(&output).contains("no-such-file.json"),
        "{}",
        stderr(&output)
    );
}

/// `-h`, `--help`, `help <command>` and — where the command has subcommands of its own —
/// `<command> help` are spellings of one question, and the CLI answers them with the same bytes on
/// stdout and a zero status, at the root and at every depth. The unit tests walk the tree and prove
/// the flags are declared alike; only running the binary proves the `help` subcommand is answered
/// by them too.
///
/// A command with no subcommands has no trailing `help`, exactly as it had none before: there,
/// `help` is a value for the positional — `permguard zones create help` names a zone.
#[test]
fn every_spelling_of_help_prints_the_same_help() {
    let dir = scratch("one-help");

    for (path, has_subcommands) in [
        (vec![], true),
        (vec!["zones"], true),
        (vec!["objects"], true),
        (vec!["zones", "create"], false),
        (vec!["decisions", "tail"], false),
        (vec!["objects", "cat"], false),
    ] {
        let mut flag = path.clone();
        flag.push("-h");
        let expected = run(&dir, &flag);

        assert!(expected.status.success(), "{path:?} -h");
        assert!(expected.stderr.is_empty(), "{path:?} -h wrote to stderr");
        assert!(
            !stdout(&expected).contains("see more with"),
            "{path:?} -h says its help is abridged"
        );

        let mut long = path.clone();
        long.push("--help");

        let mut before = vec!["help"];
        before.extend(path.iter().copied());

        let mut spellings = vec![long, before];

        if has_subcommands {
            let mut after = path.clone();
            after.push("help");
            spellings.push(after);
        }

        for spelling in spellings {
            let got = run(&dir, &spelling);

            assert_eq!(stdout(&got), stdout(&expected), "{spelling:?}");
            assert_eq!(got.status.code(), Some(0), "{spelling:?}");
        }
    }
}

/// A name that is not a command is a usage error, whether or not `help` is typed in front of it.
#[test]
fn help_for_something_that_is_not_a_command_is_a_usage_error() {
    let dir = scratch("help-unknown");
    let output = run(&dir, &["help", "nope"]);

    assert_eq!(output.status.code(), Some(64));
    assert!(output.stdout.is_empty());
    assert!(stderr(&output).contains("nope"), "{}", stderr(&output));
}

/// `permguard test` decides a workspace from its own sources — no plane, no network — and says
/// which case failed and why. The exit status is the contract a pipeline gates on: `0` all passed,
/// `2` the command ran and the workspace did not.
#[test]
fn test_runs_the_cases_of_a_workspace_offline() {
    let dir = scratch("test-cases");
    write_sources(&dir);
    run(&dir, &["init", "cases"]);

    std::fs::create_dir_all(dir.join("tests")).expect("the cases directory is created");
    std::fs::write(
        dir.join("requests/read.json"),
        r#"{"subject":{"type":"user","id":"alice"},"action":{"name":"read"},
            "resource":{"type":"document","id":"budget"}}"#,
    )
    .or_else(|_| {
        std::fs::create_dir_all(dir.join("requests")).and_then(|()| {
            std::fs::write(
                dir.join("requests/read.json"),
                r#"{"subject":{"type":"user","id":"alice"},"action":{"name":"read"},
                    "resource":{"type":"document","id":"budget"}}"#,
            )
        })
    })
    .expect("the request is written");

    // What the sources actually decide, asserted; then the same case with the answer
    // inverted, to prove the command reports a failure rather than passing everything.
    let truth = {
        std::fs::write(
            dir.join("tests/cases.yml"),
            "- name: alice reads\n  request: ../requests/read.json\n  expect: { decision: permit }\n",
        )
        .expect("the cases are written");

        let output = run(&dir, &["test", "-o", "json"]);
        let report: serde_json::Value =
            serde_json::from_str(&stdout(&output)).expect("the report is json");

        report["cases"][0]["decision"].as_bool().unwrap_or_default()
    };

    let (right, wrong) = if truth {
        ("permit", "deny")
    } else {
        ("deny", "permit")
    };

    std::fs::write(
        dir.join("tests/cases.yml"),
        format!("- name: alice reads\n  request: ../requests/read.json\n  expect: {{ decision: {right} }}\n"),
    )
    .expect("the cases are written");
    let output = run(&dir, &["test"]);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    assert!(stdout(&output).contains("1 passed"), "{}", stdout(&output));

    std::fs::write(
        dir.join("tests/cases.yml"),
        format!("- name: alice reads\n  request: ../requests/read.json\n  expect: {{ decision: {wrong} }}\n"),
    )
    .expect("the cases are written");
    let output = run(&dir, &["test"]);
    assert_eq!(
        output.status.code(),
        Some(2),
        "a failed case is the workspace's failure, not the command's"
    );
    assert!(stdout(&output).contains("1 failed"), "{}", stdout(&output));
    assert!(
        stdout(&output).contains(&format!("expected {wrong}")),
        "the report says what it expected: {}",
        stdout(&output)
    );
}

/// The three formats, and a workspace with nothing to run.
#[test]
fn test_answers_in_every_format_and_says_when_there_is_nothing_to_run() {
    let dir = scratch("test-formats");
    write_sources(&dir);
    run(&dir, &["init", "cases"]);

    let output = run(&dir, &["test"]);
    assert_eq!(output.status.code(), Some(64), "no cases is a usage error");
    assert!(stderr(&output).contains("no cases"), "{}", stderr(&output));

    std::fs::create_dir_all(dir.join("tests")).expect("the cases directory is created");
    std::fs::create_dir_all(dir.join("requests")).expect("the requests directory is created");
    std::fs::write(
        dir.join("requests/read.json"),
        r#"{"subject":{"type":"user","id":"alice"},"action":{"name":"read"},
            "resource":{"type":"document","id":"budget"}}"#,
    )
    .expect("the request is written");
    std::fs::write(
        dir.join("tests/cases.yml"),
        "- name: alice reads\n  request: ../requests/read.json\n  expect: {}\n",
    )
    .expect("the cases are written");

    for format in ["terminal", "json", "yaml"] {
        let output = run(&dir, &["-o", format, "test"]);
        assert!(output.status.success(), "{format}: {}", stderr(&output));
        assert!(!stdout(&output).is_empty(), "{format} answered nothing");
    }

    let output = run(&dir, &["test", "--list"]);
    assert!(output.status.success(), "{}", stderr(&output));
    assert!(
        stdout(&output).contains("decided none"),
        "--list decides nothing: {}",
        stdout(&output)
    );
}

/// `-w` says it is "the directory relative paths are resolved against", and every flag that names
/// a file has to mean it. Before this was true of the TLS material and of nothing else a person
/// types by hand, so `permguard -w somewhere check -f request.json` looked for the request beside
/// the terminal instead of beside the workspace.
#[test]
fn every_path_a_flag_names_is_read_from_the_working_directory() {
    let dir = scratch("workdir-contract");
    let inside = dir.join("inside");
    std::fs::create_dir_all(&inside).expect("the inner directory is created");
    std::fs::write(
        inside.join("request.json"),
        r#"{"subject":{"type":"user","id":"alice"},"action":{"name":"read"},
            "resource":{"type":"document","id":"budget"}}"#,
    )
    .expect("the request is written");
    std::fs::write(inside.join("keys.json"), r#"{"keys":[]}"#).expect("the key set is written");

    // Run from `dir`, with `-w inside`: a bare name is the workspace's, not the terminal's.
    let run_from_outside = |args: &[&str]| -> Output {
        Command::new(env!("CARGO_BIN_EXE_permguard"))
            .current_dir(&dir)
            .args(args)
            .env("PERMGUARD_CONFIG", dir.join("cli-config.yml"))
            .env_remove("PERMGUARD_TLS_CA_FILE")
            .env("NO_COLOR", "1")
            .output()
            .expect("the binary runs")
    };

    // `check -f`: found beside the workspace, so the run reaches the network and fails there.
    let output = run_from_outside(&[
        "-w",
        "inside",
        "check",
        "-f",
        "request.json",
        "--ignore-workspace",
        "--zone",
        "z",
        "--ledger",
        "l",
    ]);
    assert!(
        !stderr(&output).contains("No such file"),
        "the request was looked for outside the working directory: {}",
        stderr(&output)
    );

    // And the path that would have worked before is the one that fails now.
    let output = run_from_outside(&[
        "-w",
        "inside",
        "check",
        "-f",
        "inside/request.json",
        "--ignore-workspace",
        "--zone",
        "z",
        "--ledger",
        "l",
    ]);
    assert!(
        stderr(&output).contains("No such file"),
        "a path relative to the terminal must not resolve: {}",
        stderr(&output)
    );

    // `decisions --keys`, the same way.
    let output = run_from_outside(&[
        "-w",
        "inside",
        "decisions",
        "list",
        "--zone",
        "z",
        "--ledger",
        "l",
        "--verify",
        "--keys",
        "keys.json",
        "--control-endpoint",
        "http://127.0.0.1:1",
    ]);
    assert!(
        !stderr(&output).contains("No such file"),
        "the key set was looked for outside the working directory: {}",
        stderr(&output)
    );

    // `--config`: written and read back through the same relative name.
    let written = run_from_outside(&[
        "-w",
        "inside",
        "--config",
        "cli.yml",
        "config",
        "set",
        "control-plane.endpoint",
        "http://written.invalid:9999",
    ]);
    assert!(written.status.success(), "{}", stderr(&written));
    assert!(
        inside.join("cli.yml").exists(),
        "the configuration was written outside the working directory"
    );

    let read = run_from_outside(&[
        "-w",
        "inside",
        "--config",
        "cli.yml",
        "config",
        "get",
        "control-plane.endpoint",
    ]);
    assert!(
        stdout(&read).contains("http://written.invalid:9999"),
        "{}",
        stdout(&read)
    );

    // An absolute path is already an answer, and `-w` leaves it alone.
    let read = run_from_outside(&[
        "-w",
        "inside",
        "--config",
        inside.join("cli.yml").to_str().unwrap_or_default(),
        "config",
        "get",
        "control-plane.endpoint",
    ]);
    assert!(
        stdout(&read).contains("http://written.invalid:9999"),
        "{}",
        stdout(&read)
    );
}

/// A request the data plane would refuse is refused here too, in the same words.
///
/// This used to be the hole under the whole command: a missing `subject` became an empty type and
/// an empty id, the engines were asked about *that*, and they answered — while the same request
/// sent to a plane was refused before any policy saw it. A local run that answers where a remote
/// one refuses is the promise of `permguard test` broken quietly, so the refusal is the answer, and
/// a case may expect it.
#[test]
fn test_refuses_a_request_the_data_plane_would_refuse() {
    let dir = scratch("test-malformed");
    write_sources(&dir);
    run(&dir, &["init", "cases"]);
    std::fs::create_dir_all(dir.join("tests")).expect("the cases directory is created");
    std::fs::create_dir_all(dir.join("requests")).expect("the requests directory is created");

    for (name, request, wanted) in [
        (
            "no resource at all",
            r#"{"subject":{"type":"u","id":"a"},"action":{"name":"read"}}"#,
            "resource",
        ),
        (
            "a subject with no id",
            r#"{"subject":{"type":"u"},"action":{"name":"read"},"resource":{"type":"d","id":"b"}}"#,
            "subject.id",
        ),
        (
            "an action named by whitespace",
            r#"{"subject":{"type":"u","id":"a"},"action":{"name":"  "},"resource":{"type":"d","id":"b"}}"#,
            "action",
        ),
        // A struct reads from a sequence too, in serde and therefore in the plane: an
        // empty one is every field defaulted, and the refusal is the first field missing.
        ("a request that is a sequence", "[]", "subject"),
    ] {
        std::fs::write(dir.join("requests/probe.json"), request).expect("the request is written");

        // Expecting a decision: the refusal has to fail the case, and name the field.
        std::fs::write(
            dir.join("tests/cases.yml"),
            "- name: probe\n  request: ../requests/probe.json\n  expect: { decision: deny }\n",
        )
        .expect("the cases are written");
        let output = run(&dir, &["test"]);
        assert_eq!(
            output.status.code(),
            Some(2),
            "{name} was evaluated instead of refused: {}",
            stdout(&output)
        );
        assert!(
            stdout(&output).contains("field_required") && stdout(&output).contains(wanted),
            "{name}: the refusal does not name the field: {}",
            stdout(&output)
        );

        // And expecting the refusal: the case passes, the same way it would against a plane.
        std::fs::write(
            dir.join("tests/cases.yml"),
            "- name: probe\n  request: ../requests/probe.json\n  expect: { error: field_required }\n",
        )
        .expect("the cases are written");
        let output = run(&dir, &["test"]);
        assert!(
            output.status.success(),
            "{name}: a case may expect the refusal: {}",
            stdout(&output)
        );
    }
}

/// A payload of the wrong JSON *type* is refused here too, and with the plane's own code.
///
/// The plane deserializes into typed bodies, so a `context` of `"invalid"` never reaches a policy
/// there. Defaulting it to an empty object here would have this command answer where a plane
/// refuses — the same divergence as a missing field, one layer down.
#[test]
fn test_refuses_a_payload_the_data_plane_would_not_read() {
    let dir = scratch("test-types");
    write_sources(&dir);
    run(&dir, &["init", "cases"]);
    std::fs::create_dir_all(dir.join("tests")).expect("the cases directory is created");
    std::fs::create_dir_all(dir.join("requests")).expect("the requests directory is created");

    let whole = |extra: &str| {
        format!(
            r#"{{"subject":{{"type":"u","id":"a"}},"action":{{"name":"read"}},
                "resource":{{"type":"d","id":"b"}}{extra}}}"#
        )
    };

    for (name, request) in [
        (
            "a context that is not an object",
            whole(r#","context":"invalid""#),
        ),
        (
            "a principal that is not an entity",
            whole(r#","principal":"invalid""#),
        ),
        (
            "options that are not an object",
            whole(r#","options":"invalid""#),
        ),
        (
            "a semantic the contract does not have",
            whole(r#","options":{"evaluations_semantic":"whenever"}"#),
        ),
        (
            "a request_id that is not a string",
            whole(r#","request_id":7"#),
        ),
        (
            "evaluations that are not a list",
            whole(r#","evaluations":"invalid""#),
        ),
        (
            "an entity schema that is not a string",
            whole(r#","entities":{"schema":7,"items":[]}"#),
        ),
        (
            "entity items that are null",
            whole(r#","entities":{"items":null}"#),
        ),
        (
            "entities that are not an object",
            whole(r#","entities":"invalid""#),
        ),
        (
            "entity items that are not a list",
            whole(r#","entities":{"items":"invalid"}"#),
        ),
        (
            "properties that are not an object",
            r#"{"subject":{"type":"u","id":"a","properties":"invalid"},
                "action":{"name":"read"},"resource":{"type":"d","id":"b"}}"#
                .to_owned(),
        ),
        (
            "a type that is not a string",
            r#"{"subject":{"type":7,"id":"a"},"action":{"name":"read"},
                "resource":{"type":"d","id":"b"}}"#
                .to_owned(),
        ),
        (
            "a subject that is not an object",
            r#"{"subject":"alice","action":{"name":"read"},"resource":{"type":"d","id":"b"}}"#
                .to_owned(),
        ),
    ] {
        std::fs::write(dir.join("requests/probe.json"), &request).expect("the request is written");
        std::fs::write(
            dir.join("tests/cases.yml"),
            "- name: probe\n  request: ../requests/probe.json\n  expect: { decision: deny }\n",
        )
        .expect("the cases are written");

        let output = run(&dir, &["test"]);
        assert_eq!(
            output.status.code(),
            Some(2),
            "{name} was evaluated instead of refused: {}",
            stdout(&output)
        );
        assert!(
            stdout(&output).contains("payload_malformed"),
            "{name}: not reported the way a plane reports it: {}",
            stdout(&output)
        );

        std::fs::write(
            dir.join("tests/cases.yml"),
            "- name: probe\n  request: ../requests/probe.json\n  expect: { error: payload_malformed }\n",
        )
        .expect("the cases are written");
        assert!(
            run(&dir, &["test"]).status.success(),
            "{name}: a case may expect the refusal"
        );
    }
}

/// A profile the ledger does not declare is `profile_unknown` here as it is there.
#[test]
fn test_reports_an_unknown_profile_the_way_a_plane_reports_it() {
    let dir = scratch("test-profile");
    write_sources(&dir);
    run(&dir, &["init", "cases"]);
    std::fs::create_dir_all(dir.join("tests")).expect("the cases directory is created");
    std::fs::create_dir_all(dir.join("requests")).expect("the requests directory is created");
    std::fs::write(
        dir.join("requests/probe.json"),
        r#"{"subject":{"type":"u","id":"a"},"action":{"name":"read"},
            "resource":{"type":"d","id":"b"}}"#,
    )
    .expect("the request is written");

    std::fs::write(
        dir.join("tests/cases.yml"),
        "- name: probe\n  request: ../requests/probe.json\n  profile: nowhere\n  expect: { decision: permit }\n",
    )
    .expect("the cases are written");
    let output = run(&dir, &["test"]);
    assert_eq!(output.status.code(), Some(2), "{}", stdout(&output));
    assert!(
        stdout(&output).contains("profile_unknown"),
        "{}",
        stdout(&output)
    );

    // And a case may expect it, which before went through a path that never looked at
    // the expectation at all.
    std::fs::write(
        dir.join("tests/cases.yml"),
        "- name: probe\n  request: ../requests/probe.json\n  profile: nowhere\n  expect: { error: profile_unknown }\n",
    )
    .expect("the cases are written");
    assert!(
        run(&dir, &["test"]).status.success(),
        "a case may expect an unknown profile"
    );
}

/// Inside a boxcarred batch, every evaluation's policies are named — and an identity this
/// workspace does not contain is reported as drift.
///
/// `Answered::of` leaves a batch's *overall* policies empty, because a batch has no single policy
/// to cite. That used to mean the per-evaluation ones were never looked at, so `--remote` accepted
/// a batch decided by another commit's policies whenever the booleans lined up.
#[test]
fn test_names_the_policies_of_every_evaluation_in_a_batch() {
    let dir = scratch("test-batch-policies");
    write_sources(&dir);
    run(&dir, &["init", "batch"]);
    std::fs::create_dir_all(dir.join("tests")).expect("the cases directory is created");
    std::fs::create_dir_all(dir.join("requests")).expect("the requests directory is created");
    std::fs::write(
        dir.join("requests/batch.json"),
        r#"{"subject":{"type":"user","id":"alice"},"resource":{"type":"document","id":"budget"},
            "evaluations":[{"action":{"name":"read"},"request_id":"first"},
                           {"action":{"name":"write"},"request_id":"second"}]}"#,
    )
    .expect("the request is written");
    std::fs::write(
        dir.join("tests/cases.yml"),
        "- name: two in one\n  request: ../requests/batch.json\n  expect: {}\n",
    )
    .expect("the cases are written");

    let output = run(&dir, &["test"]);
    assert!(output.status.success(), "{}", stderr(&output));

    // Each evaluation is reported by its own name and its own answer, and where something
    // permitted it, by the alias of what did — not by the identity underneath.
    let report = stdout(&output);
    assert!(
        report.contains("first=") && report.contains("second="),
        "the evaluations are not reported one by one: {report}"
    );
    assert!(
        !report.contains("no policy of this workspace"),
        "the workspace's own policies were not recognised: {report}"
    );
    assert!(
        report.contains('('),
        "no evaluation names what decided it: {report}"
    );

    // And a case may name what each one must answer.
    std::fs::write(
        dir.join("tests/cases.yml"),
        "- name: two in one\n  request: ../requests/batch.json\n  expect:\n    evaluations: { first: deny, second: deny }\n",
    )
    .expect("the cases are written");
    let output = run(&dir, &["test"]);
    let wrong = !output.status.success();
    assert!(
        wrong || report.contains("first=deny"),
        "a per-evaluation expectation is not checked: {}",
        stdout(&output)
    );

    // An evaluation the request never asked is a mistake in the case, and is said so.
    std::fs::write(
        dir.join("tests/cases.yml"),
        "- name: two in one\n  request: ../requests/batch.json\n  expect:\n    evaluations: { third: permit }\n",
    )
    .expect("the cases are written");
    let output = run(&dir, &["test"]);
    assert_eq!(output.status.code(), Some(2), "{}", stdout(&output));
    assert!(
        stdout(&output).contains("no evaluation named `third`"),
        "{}",
        stdout(&output)
    );
}
