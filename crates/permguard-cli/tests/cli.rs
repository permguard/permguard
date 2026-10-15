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
            "profiles:\n  default: { type: permguard.api.pdp.native.v1, partitions: [app] }\n",
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
            "http://10.0.0.9:6443",
        ],
    );
    assert!(set.status.success(), "{}", stderr(&set));

    let get = run(&dir, &["config", "get", "control-plane.endpoint"]);
    assert_eq!(stdout(&get).trim(), "http://10.0.0.9:6443");

    let show = run(&dir, &["-o", "json", "config", "show"]);
    assert!(stdout(&show).contains("10.0.0.9"), "{}", stdout(&show));

    let reset = run(&dir, &["config", "reset", "control-plane.endpoint"]);
    assert!(reset.status.success(), "{}", stderr(&reset));
    let get = run(&dir, &["config", "get", "control-plane.endpoint"]);
    assert!(stdout(&get).contains("127.0.0.1:6443"), "{}", stdout(&get));
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

/// A workspace is the manifest, the partitions it declares, `.permguardignore` and `.permguard/`:
/// anything else is refused, not skipped. `notes.txt` at the root is refused by name with the
/// three ways out; `app/typo.cedr` inside a partition — a policy nobody would ever enforce — is
/// refused the same way; and the file `init` wrote is where the usual neighbours are excused.
#[test]
fn a_file_the_workspace_does_not_know_is_refused_until_it_is_moved_removed_or_ignored() {
    let dir = scratch("dirt");
    write_sources(&dir);
    run(&dir, &["init", "dirt"]);
    let ignores = std::fs::read_to_string(dir.join(".permguardignore")).expect("init wrote it");
    assert!(ignores.contains("tests/"), "{ignores}");

    std::fs::write(dir.join("notes.txt"), "todo\n").expect("the note is written");
    std::fs::write(
        dir.join("app/typo.cedr"),
        "permit(principal, action, resource);\n",
    )
    .expect("the typo is written");
    let refused = run(&dir, &["validate"]);
    assert_eq!(refused.status.code(), Some(64), "{}", stderr(&refused));
    let said = stderr(&refused);
    for expected in ["notes.txt", "app/typo.cedr", ".permguardignore"] {
        assert!(said.contains(expected), "{said}");
    }

    std::fs::remove_file(dir.join("app/typo.cedr")).expect("the typo is removed");
    std::fs::write(
        dir.join(".permguardignore"),
        format!("{ignores}notes.txt\n"),
    )
    .expect("the note is excused");
    // What the Finder drops is known without being named, at the root and inside a partition.
    std::fs::write(dir.join(".DS_Store"), "").expect("the Finder was here");
    std::fs::write(dir.join("app/.DS_Store"), "").expect("and here");
    let valid = run(&dir, &["validate"]);
    assert!(valid.status.success(), "{}", stderr(&valid));
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
    let output = run(&dir, &["--endpoint", "127.0.0.1:6443", "zones", "list"]);

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
    assert_eq!(output.status.code(), Some(69));
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
        (vec!["events"], true),
        (vec!["zones", "create"], false),
        (vec!["decisions", "tail"], false),
        (vec!["events", "list"], false),
        (vec!["events", "verify"], false),
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
        "- name: alice reads\n  request: ../requests/read.json\n  expect: { decision: permit, policies: [readers] }\n",
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

/// A `--name` that matches nothing names the filter and what it was applied to. It used to say the
/// workspace had no `tests` folder — right after reading that folder and finding cases in it.
#[test]
fn a_name_filter_that_matches_nothing_names_the_filter_not_a_missing_folder() {
    let dir = scratch("test-name-filter");
    write_sources(&dir);
    run(&dir, &["init", "cases"]);
    write_one_case(&dir);

    let output = run(&dir, &["test", "--name", "zzz-nonexistent"]);
    assert_eq!(output.status.code(), Some(64), "{}", stderr(&output));
    let said = stderr(&output);
    assert!(said.contains("no cases"), "{said}");
    assert!(
        said.contains("zzz-nonexistent"),
        "the filter is named: {said}"
    );
    assert!(
        said.contains("1 case(s)"),
        "and what it was applied to: {said}"
    );
    assert!(
        !said.contains("has no `tests` folder"),
        "the folder was read, and is not to blame: {said}"
    );
}

/// One file that is not a list of cases does not stop the others: the valid case runs, the broken
/// file is reported beside it, and the run is not green.
#[test]
fn a_file_that_does_not_read_as_cases_is_reported_and_the_others_still_run() {
    let dir = scratch("test-broken-file");
    write_sources(&dir);
    run(&dir, &["init", "cases"]);
    write_one_case(&dir);
    std::fs::write(dir.join("tests/broken.yml"), "invalid: yaml: [[[\n").expect("the broken file");

    let output = run(&dir, &["test", "--name", "alice reads"]);
    assert_eq!(
        output.status.code(),
        Some(2),
        "a broken file is a failed run, not a usage error: {}",
        stderr(&output)
    );
    let said = stdout(&output);
    assert!(said.contains("alice reads"), "the valid case ran: {said}");
    assert!(
        said.contains("tests/broken.yml"),
        "the broken file is named: {said}"
    );
    assert!(said.contains("1 file(s) could not be read"), "{said}");

    let output = run(&dir, &["-o", "json", "test"]);
    let report: serde_json::Value =
        serde_json::from_str(&stdout(&output)).expect("the JSON report parses");
    assert_eq!(
        report["unreadable"].as_array().map(Vec::len),
        Some(1),
        "{report}"
    );
    assert_eq!(
        report["unreadable"][0]["source"], "tests/broken.yml",
        "{report}"
    );
    assert_eq!(
        report["cases"].as_array().map(Vec::len),
        Some(1),
        "{report}"
    );
    // Every case line has every field, whatever it decided.
    for field in ["decision", "policies", "evaluations", "error", "problems"] {
        assert!(
            report["cases"][0].get(field).is_some(),
            "`{field}` is present on every case: {report}"
        );
    }
}

/// One case beside its request, the way `test_answers_in_every_format…` writes them.
fn write_one_case(dir: &Path) {
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
        "- name: alice reads\n  request: ../requests/read.json\n  expect: { decision: permit, policies: [readers] }\n",
    )
    .expect("the cases are written");
}

/// A value that cannot mean anything is refused where it is typed, before any network: a size or
/// a limit of zero, an empty commit message, a `--since` that is not a timestamp, and a document
/// sent beside the flags that would describe another request.
#[test]
fn a_value_that_cannot_mean_anything_is_refused_before_any_network() {
    let dir = scratch("refused-values");
    write_sources(&dir);
    run(&dir, &["init", "refused"]);
    std::fs::write(dir.join("request.json"), "{}").expect("the request is written");

    let scope = [
        "--zone",
        "z",
        "--ledger",
        "l",
        "--control-endpoint",
        "http://127.0.0.1:1",
    ];
    let cases: Vec<(Vec<&str>, &str)> = vec![
        (vec!["zones", "list", "--size", "0"], "--size"),
        (vec!["history", "--limit", "0"], "at least 1"),
        (vec!["apply", "-m", ""], "cannot be empty"),
        (
            vec!["check", "-f", "request.json", "--subject", "user:alice"],
            "cannot be used with",
        ),
    ];
    let mut cases = cases;
    for (flag, value, said) in [
        ("--limit", "0", "at least 1"),
        ("--since", "not-a-date", "RFC 3339"),
        ("--since", "1789981824", "RFC 3339"),
        ("--since", "", "RFC 3339"),
    ] {
        let mut argv = vec!["decisions", "list", flag, value];
        argv.extend(scope);
        cases.push((argv, said));
    }

    for (argv, said) in cases {
        let output = run(&dir, &argv);
        assert!(!output.status.success(), "{argv:?} was accepted");
        assert!(
            stderr(&output).contains(said),
            "{argv:?} did not say `{said}`: {}",
            stderr(&output)
        );
    }
}

/// Pages count from zero, as every C-like interface counts: `--page 0` is the first page, not a
/// value refused where it is typed. The endpoint answers nothing, so the outcome is the plane
/// being unavailable — which is what proves the request left the parser.
#[test]
fn page_zero_is_the_first_page_and_reaches_the_network() {
    let dir = scratch("page-zero");
    let output = run(
        &dir,
        &[
            "zones",
            "list",
            "--page",
            "0",
            "--control-endpoint",
            "http://127.0.0.1:1",
            "-o",
            "json",
        ],
    );

    let said = stderr(&output);
    assert_eq!(output.status.code(), Some(69), "{said}");
    assert!(!said.contains("--page"), "{said}");
    let failure: serde_json::Value =
        serde_json::from_str(&said).unwrap_or_else(|error| panic!("{said}: {error}"));
    assert_eq!(failure["class"], "unavailable", "{said}");
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
            "partition inputs that are not an object",
            whole(r#","partition_inputs":"invalid""#),
        ),
        (
            "a partition input that is not an object",
            whole(r#","partition_inputs":{"admin-cedar":"invalid"}"#),
        ),
        (
            "a partition input type that is not a string",
            whole(r#","partition_inputs":{"admin-cedar":{"type":7,"data":[]}}"#),
        ),
        (
            "partition inputs that are null",
            whole(r#","partition_inputs":null"#),
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
        "- name: two in one\n  request: ../requests/batch.json\n  expect: { decision: permit }\n",
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

/// Reading events with no scope says which ways there are, exactly as reading decisions does.
///
/// The two evidence logs are read the same way and refused the same way. A caller who learned one
/// has learned the other, and a script that switched between them would otherwise have to parse two
/// vocabularies for the same mistake.
#[test]
fn reading_events_without_a_scope_says_which_ways_there_are() {
    let dir = scratch("events-scope");
    let output = run(
        &dir,
        &["events", "list", "--control-endpoint", "http://127.0.0.1:1"],
    );

    assert_eq!(output.status.code(), Some(64));
    let said = stderr(&output);
    for hint in ["--zone", "workspace"] {
        assert!(said.contains(hint), "{said}");
    }
}

/// An event log that cannot be reached is unavailable, not a usage error.
///
/// The distinction a script depends on: nothing the operator typed is wrong, so retrying later is
/// the right response, and the exit code is what says which of the two it was.
#[test]
fn an_event_log_that_cannot_be_reached_is_unavailable_not_a_usage_error() {
    let dir = scratch("events-down");
    let output = run(
        &dir,
        &[
            "events",
            "list",
            "--zone",
            "acme",
            "--ledger",
            "agent-governance",
            "--control-endpoint",
            "http://127.0.0.1:1",
            "-o",
            "json",
        ],
    );

    assert_eq!(output.status.code(), Some(69));
    let said = stderr(&output);
    let failure: serde_json::Value =
        serde_json::from_str(&said).unwrap_or_else(|error| panic!("{said}: {error}"));
    assert_eq!(failure["class"], "unavailable", "{said}");
    assert!(
        failure["code"]
            .as_str()
            .is_some_and(|code| !code.is_empty()),
        "a structured failure carries a code a script can switch on: {said}"
    );
}

/// Every `events` refusal answers in all three formats, and only ever on stderr.
///
/// # What this is actually about
///
/// The output contract is not "there is a `-o json`". It is that *every* command answers through
/// one report, so the same failure is the same failure in all three renderings — and that a
/// structured rendering never leaks onto stdout, where a script capturing the answer would find a
/// refusal parsed as data.
#[test]
fn events_answers_in_all_three_formats_and_keeps_refusals_off_stdout() {
    let dir = scratch("events-formats");

    for format in ["terminal", "json", "yaml"] {
        let output = run(
            &dir,
            &[
                "events",
                "list",
                "--zone",
                "acme",
                "--ledger",
                "agent-governance",
                "--control-endpoint",
                "http://127.0.0.1:1",
                "-o",
                format,
            ],
        );

        assert_eq!(output.status.code(), Some(69), "{format}");
        assert!(
            output.stdout.is_empty(),
            "{format}: a refusal reached stdout: {}",
            stdout(&output)
        );
        let said = stderr(&output);
        match format {
            "json" => {
                let failure: serde_json::Value =
                    serde_json::from_str(&said).unwrap_or_else(|error| panic!("{said}: {error}"));
                assert_eq!(failure["class"], "unavailable", "{said}");
            }
            "yaml" => {
                let failure: serde_json::Value =
                    serde_norway::from_str(&said).unwrap_or_else(|error| panic!("{said}: {error}"));
                assert_eq!(failure["class"], "unavailable", "{said}");
            }
            _ => assert!(
                !said.trim().is_empty() && !said.starts_with('{'),
                "the terminal rendering is prose, not a structure: {said}"
            ),
        }
    }
}

/// An export carries its evidence, so verifying a file never depends on the server that supplied
/// it still being reachable. Empty is a legitimate complete snapshot and a useful transport test:
/// any accidental network call would hit the deliberately unreachable endpoint below.
#[test]
fn an_event_export_is_verified_offline_in_every_output_format() {
    let dir = scratch("events-offline-verify");
    let archive = dir.join("events.json");
    std::fs::write(
        dir.join("producer-keys.json"),
        r#"{"keys":[{"kid":"unused","kty":"OKP","crv":"Ed25519","x":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","alg":"EdDSA","use":"sig"}]}"#,
    )
    .expect("the independent key set writes");
    std::fs::write(
        &archive,
        r#"{
          "format":"permguard.events.export.v1alpha1",
          "scope_binding":{"kind":"tenant","zone":"acme","ledger":"main"},
          "summary":{
            "scope":"acme/main","events":[],"next":"end","high_watermark":"end",
            "more":false,"coverage":{"contiguous":false,"examined":0,"scan_bounded":false}
          },
          "records":[],"envelopes":[],"inclusion":[]
        }"#,
    )
    .expect("the archive writes");

    for format in ["terminal", "json", "yaml"] {
        let output = run(
            &dir,
            &[
                "events",
                "verify",
                "--file",
                "events.json",
                "--keys",
                "producer-keys.json",
                "--control-endpoint",
                "http://127.0.0.1:1",
                "-o",
                format,
            ],
        );
        assert!(output.status.success(), "{format}: {}", stderr(&output));
        assert!(output.stderr.is_empty(), "{format}: {}", stderr(&output));
        if format == "json" {
            let report: serde_json::Value =
                serde_json::from_str(&stdout(&output)).expect("the report is JSON");
            assert_eq!(report["verified"]["included"], 0);
            assert_eq!(report["verified"]["signatures_checked"], true);
        }
    }
}

#[test]
fn event_verification_refuses_to_trust_proof_material_without_a_producer_key() {
    let dir = scratch("events-verify-keys");
    std::fs::write(
        dir.join("events.json"),
        r#"{
          "format":"permguard.events.export.v1alpha1",
          "scope_binding":{"kind":"tenant","zone":"acme","ledger":"main"},
          "summary":{"scope":"acme/main","events":[],"next":"end","high_watermark":"end",
            "more":false,"coverage":{"contiguous":false,"examined":0,"scan_bounded":false}},
          "records":[],"envelopes":[],"inclusion":[]
        }"#,
    )
    .expect("the archive writes");

    let output = run(&dir, &["events", "verify", "--file", "events.json"]);
    assert_eq!(output.status.code(), Some(64), "{}", stderr(&output));
    assert!(stderr(&output).contains("event_keys_required"));
    assert!(output.stdout.is_empty());
}

/// `-v` narrates the exchange to stderr, and says nothing extra without it.
///
/// Quiet by default and explicit on demand. The narration goes to stderr because stdout is the
/// answer, and an operator who asked for detail must not thereby change what a pipe receives.
#[test]
fn events_narrates_the_exchange_only_when_asked() {
    let dir = scratch("events-verbose");
    let asked = &[
        "events",
        "list",
        "--zone",
        "acme",
        "--ledger",
        "agent-governance",
        "--control-endpoint",
        "http://127.0.0.1:1",
    ];

    let quiet = run(&dir, asked);
    assert!(
        !stderr(&quiet).contains("[verbose]"),
        "unasked: {}",
        stderr(&quiet)
    );

    let mut verbose = asked.to_vec();
    verbose.push("-v");
    let loud = run(&dir, &verbose);
    assert!(
        stderr(&loud).contains("[verbose]"),
        "asked: {}",
        stderr(&loud)
    );
    assert!(
        stderr(&loud).contains("http://127.0.0.1:1"),
        "and it names the endpoint it tried: {}",
        stderr(&loud)
    );
    assert_eq!(
        loud.status.code(),
        quiet.status.code(),
        "asking for narration does not change the outcome"
    );
}

/// The most powerful read in the system is not something a flag can be given by accident.
///
/// `--all-zones` reads every tenant's events. It is the one read a mistake in a script must not
/// silently widen into, so it is refused unless it is asked for on its own terms.
#[test]
fn reading_every_tenants_events_is_refused_unless_it_is_asked_for_alone() {
    let dir = scratch("events-all-zones");
    let output = run(
        &dir,
        &[
            "events",
            "list",
            "--all-zones",
            "--zone",
            "acme",
            "--control-endpoint",
            "http://127.0.0.1:1",
        ],
    );

    assert_eq!(output.status.code(), Some(64), "{}", stderr(&output));
    assert!(output.stdout.is_empty());
}

/// The shipped Dogwood example's test plan runs, offline, and every case passes.
///
/// # Why this test and not a unit one
///
/// A temporal case is a claim about *order*, and until `permguard test` could express one, the
/// shipped example had no test plan at all: `permguard test` answered "no cases", and the README's
/// table of outcomes was prose nothing checked. What this pins down is the whole path — the case
/// format, the events applied in order, the history reset between cases, and the example's own
/// files — against the outcomes its README states.
///
/// The reset is the part most likely to rot. The compiled partitions are shared across a run, so a
/// case that forgot to clear the histories would read the previous case's events; the plan below
/// contains the exact pair that catches it — one read permitted by a login before it, and the same
/// read with no login, which must be denied.
#[test]
fn the_shipped_dogwood_example_passes_its_own_test_plan() {
    let example = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../examples/dogwood-session-access")
        .canonicalize()
        .expect("the shipped example is where the repository keeps it");

    let dir = scratch("dogwood-plan");
    std::fs::create_dir_all(&dir).expect("the workspace directory is created");
    for relative in [
        "manifest.yml",
        ".permguardignore",
        "governance/read-after-login.dw",
        "governance/schema.cedarschema",
        "governance/events.dwschema",
        "tests/session-access.yml",
        "events/1-login-request.json",
        "events/2-login-response.json",
        "requests/1-read-before-login.json",
        "requests/2-read-inside-window.json",
        "requests/3-read-outside-window.json",
        "requests/4-read-other-user.json",
        "refusals/unknown-action.json",
        "refusals/undeclared-field.json",
        "refusals/pin-disagrees.json",
    ] {
        let target = dir.join(relative);
        if let Some(parent) = target.parent() {
            std::fs::create_dir_all(parent).expect("the directory is created");
        }
        std::fs::copy(example.join(relative), &target)
            .unwrap_or_else(|error| panic!("{relative}: {error}"));
    }

    let output = run(&dir, &["test", "-o", "json"]);
    let report: serde_json::Value =
        serde_json::from_str(&stdout(&output)).expect("the report is json");
    let cases = report["cases"].as_array().expect("it lists the cases");
    assert!(
        cases.len() >= 8,
        "the example's plan covers its README's table: {}",
        cases.len()
    );
    for case in cases {
        assert_eq!(case["passed"], true, "`{}` failed: {}", case["name"], case);
        assert_eq!(
            case["profile"], "temporal",
            "every case runs under the profile the request names: {case}"
        );
    }
    assert!(
        output.status.success(),
        "a plan whose cases all pass exits zero"
    );

    // And the ordering claim is the one under test: the same read decides differently depending
    // only on what happened before it.
    let named = |name: &str| -> serde_json::Value {
        cases
            .iter()
            .find(|case| case["name"] == name)
            .unwrap_or_else(|| panic!("the plan has a case named `{name}`"))
            .clone()
    };
    assert_eq!(
        named("a read inside the window is permitted by the login before it")["decision"],
        true
    );
    assert_eq!(
        named("the same read with no login before it is denied")["decision"],
        false,
        "the histories are reset between cases, or this reads the previous case's login"
    );
}

/// TC-1: a command names exactly one target class, and a flag naming another is a usage error,
/// never a fallback from one plane or Host to another.
#[test]
fn a_command_names_one_target_class_and_never_falls_back() {
    let dir = scratch("target-class");
    for (args, flag) in [
        (
            vec!["zones", "list", "--data-endpoint", "https://127.0.0.1:1"],
            "--data-endpoint",
        ),
        (
            vec!["zones", "list", "--host-endpoint", "https://127.0.0.1:1"],
            "--host-endpoint",
        ),
        (
            vec!["check", "--control-endpoint", "https://127.0.0.1:1"],
            "--control-endpoint",
        ),
        (vec!["decisions", "list", "--volume", "."], "--volume"),
        (
            vec!["inspect", "--host-endpoint", "https://127.0.0.1:1"],
            "--host-endpoint",
        ),
        (
            vec![
                "host",
                "identity",
                "show",
                "--control-endpoint",
                "https://127.0.0.1:1",
            ],
            "--control-endpoint",
        ),
        (
            vec!["validate", "--data-endpoint", "https://127.0.0.1:1"],
            "--data-endpoint",
        ),
        (
            vec!["test", "--control-endpoint", "https://127.0.0.1:1"],
            "--control-endpoint",
        ),
    ] {
        let output = run(&dir, &args);
        assert_eq!(
            output.status.code(),
            Some(64),
            "{args:?}: {}",
            stderr(&output)
        );
        assert!(
            stderr(&output).contains(flag),
            "{args:?}: {}",
            stderr(&output)
        );
        assert!(
            stderr(&output).contains("never falls back"),
            "{args:?}: {}",
            stderr(&output)
        );
        assert!(output.stdout.is_empty(), "{args:?}");
    }
    // Its own class is accepted: both plane endpoints for the multi-target probe.
    let output = run(
        &dir,
        &[
            "inspect",
            "--control-endpoint",
            "http://127.0.0.1:1",
            "--data-endpoint",
            "http://127.0.0.1:1",
            "--timeout",
            "1",
        ],
    );
    assert_eq!(output.status.code(), Some(1), "{}", stderr(&output));
}

/// WP-4.8: every normative Host command is present before a request is sent.
#[test]
fn the_host_identity_members_and_grants_command_families_are_complete() {
    let dir = scratch("host-command-families");
    for path in [
        &["host", "identity", "verify", "--help"][..],
        &["host", "identity", "pin", "add", "--help"],
        &["host", "members", "invite", "create", "--help"],
        &["host", "members", "join", "--help"],
        &["host", "members", "pending", "--help"],
        &["host", "members", "approve", "--help"],
        &["host", "members", "sessions", "--help"],
        &["host", "members", "verify", "--help"],
        &["host", "grants", "revoke", "plan", "--help"],
        &["host", "grants", "revoke", "run", "--help"],
    ] {
        let output = run(&dir, path);
        assert!(output.status.success(), "{path:?}: {}", stderr(&output));
    }
}

/// WP-4.8/TC-1: provisioning remains offline and takes the global `--volume` wherever written.
#[test]
fn the_offline_host_commands_take_the_global_volume() {
    let dir = scratch("global-volume");
    let before_volume = dir.join("before-volume").display().to_string();
    let before = run(
        &dir,
        &[
            "--volume",
            &before_volume,
            "host",
            "identity",
            "provision",
            "-o",
            "json",
        ],
    );
    assert!(before.status.success(), "{}", stderr(&before));
    let after_volume = dir.join("after-volume").display().to_string();
    let after = run(
        &dir,
        &[
            "host",
            "identity",
            "provision",
            "--volume",
            &after_volume,
            "-o",
            "json",
        ],
    );
    assert!(after.status.success(), "{}", stderr(&after));
    let missing = run(&dir, &["host", "identity", "provision"]);
    assert_eq!(missing.status.code(), Some(64), "{}", stderr(&missing));
    assert!(
        stderr(&missing).contains("--volume"),
        "{}",
        stderr(&missing)
    );
}

/// TC-1: the token file is the operator's alone, and holds one printable word.
#[test]
fn the_token_file_is_refused_when_others_can_read_it_or_it_is_empty() {
    let dir = scratch("token-file");
    let token = dir.join("token");
    let refused = |contents: &str, mode: u32| {
        std::fs::write(&token, contents).expect("written");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&token, std::fs::Permissions::from_mode(mode)).expect("chmod");
        }
        let _ = mode;
        let output = run(
            &dir,
            &[
                "zones",
                "list",
                "--token-file",
                &token.display().to_string(),
                "--control-endpoint",
                "https://127.0.0.1:1",
            ],
        );
        (output.status.code(), stderr(&output))
    };
    #[cfg(unix)]
    {
        let (code, why) = refused("op-token-secret-value\n", 0o644);
        assert_eq!(code, Some(64), "{why}");
        assert!(why.contains("open to its group or to others"), "{why}");
        assert!(!why.contains("op-token-secret-value"), "{why}");
    }
    let (code, why) = refused("  \n", 0o600);
    assert_eq!(code, Some(64), "{why}");
    assert!(why.contains("is empty"), "{why}");
    let (code, why) = refused("two words\n", 0o600);
    assert_eq!(code, Some(64), "{why}");
    assert!(why.contains("one printable word"), "{why}");
    // A good one reaches the transport: nothing listens, so the target is unavailable.
    let (code, why) = refused("op-token-secret-value\n", 0o600);
    assert_eq!(code, Some(69), "{why}");
    assert!(!why.contains("op-token-secret-value"), "{why}");
    // A FIFO is not a token file, and opening one would wait for a writer forever: refused
    // before it is opened.
    #[cfg(unix)]
    {
        let fifo = dir.join("token.fifo");
        let made = Command::new("mkfifo").arg(&fifo).status();
        if made.is_ok_and(|status| status.success()) {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&fifo, std::fs::Permissions::from_mode(0o600)).expect("chmod");
            let output = run(
                &dir,
                &[
                    "zones",
                    "list",
                    "--token-file",
                    &fifo.display().to_string(),
                    "--control-endpoint",
                    "https://127.0.0.1:1",
                ],
            );
            assert_eq!(output.status.code(), Some(64), "{}", stderr(&output));
            assert!(
                stderr(&output).contains("not a regular file"),
                "{}",
                stderr(&output)
            );
        }
    }
    // A directory is not a token file.
    let directory = dir.join("not-a-file");
    std::fs::create_dir_all(&directory).expect("created");
    let output = run(
        &dir,
        &[
            "zones",
            "list",
            "--token-file",
            &directory.display().to_string(),
            "--control-endpoint",
            "https://127.0.0.1:1",
        ],
    );
    assert_eq!(output.status.code(), Some(64), "{}", stderr(&output));
    // The token goes only over verified TLS (owner decision): in the clear, or with verification
    // skipped, the command is refused before anything is sent.
    for (endpoint, skip) in [
        ("http://127.0.0.1:1", false),
        ("grpc://127.0.0.1:1", false),
        ("https://127.0.0.1:1", true),
    ] {
        let mut args = vec![
            "zones",
            "list",
            "--token-file",
            token.to_str().expect("utf-8"),
            "--control-endpoint",
            endpoint,
        ];
        if skip {
            args.push("--tls-skip-verify");
        }
        let output = run(&dir, &args);
        assert_eq!(
            output.status.code(),
            Some(64),
            "{endpoint}: {}",
            stderr(&output)
        );
        assert!(
            stderr(&output).contains("only over verified TLS"),
            "{endpoint}: {}",
            stderr(&output)
        );
    }
}

/// WP-4.8: an invitation is a secret, so an insecure join target is rejected before the
/// invitation path is inspected, let alone opened.
#[test]
fn host_members_join_rejects_insecure_transports_before_reading_the_invitation() {
    let dir = scratch("join-insecure-before-token");
    let missing = dir.join("secret-invitation-that-must-not-be-read.json");

    for scheme in ["http", "grpc"] {
        let endpoint = format!("{scheme}://127.0.0.1:1");
        let output = run(
            &dir,
            &[
                "--host-endpoint",
                &endpoint,
                "--token-file",
                missing.to_str().expect("utf-8"),
                "host",
                "members",
                "join",
                &endpoint,
                "--pin-fingerprint",
                "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            ],
        );
        let why = stderr(&output);
        assert_eq!(output.status.code(), Some(64), "{scheme}: {why}");
        assert!(why.contains("only over verified TLS"), "{scheme}: {why}");
        assert!(!why.contains("secret-invitation"), "{scheme}: {why}");
    }
}

#[test]
fn host_members_join_uses_only_an_explicit_fingerprint_or_an_exact_local_pin() {
    const URL: &str = "https://127.0.0.1:1";
    const OTHER_URL: &str = "https://127.0.0.1:2";
    const HOST: &str = "0198f2aa-0000-7000-8000-000000000001";
    const OTHER_HOST: &str = "0198f2aa-0000-7000-8000-000000000002";
    const FINGERPRINT: &str =
        "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const OTHER_FINGERPRINT: &str =
        "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";

    let handoff = |dir: &Path| {
        let path = dir.join("invitation.json");
        std::fs::write(
            &path,
            format!(
                "{{\"version\":1,\"coordinator\":{{\"address\":\"{URL}\",\"host_id\":\"{HOST}\",\"fingerprint\":\"{FINGERPRINT}\"}},\"invite_id\":\"0198f2aa-0000-7000-8000-000000000003\",\"token\":\"private-token\",\"requested\":{{\"selector\":\"plane/data/*\",\"tasks\":[]}},\"expires\":\"2030-01-01T00:00:00Z\"}}"
            ),
        )
        .expect("the handoff writes");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
                .expect("the handoff is private");
        }
    };
    let add = |dir: &Path, url: &str, host: &str, fingerprint: &str| {
        let output = run(
            dir,
            &[
                "host",
                "identity",
                "pin",
                "add",
                url,
                "--host-id",
                host,
                "--fingerprint",
                fingerprint,
            ],
        );
        assert!(output.status.success(), "{}", stderr(&output));
    };
    let join = |dir: &Path, explicit: Option<&str>| {
        let mut args = vec![
            "--host-endpoint",
            URL,
            "--token-file",
            "invitation.json",
            "host",
            "members",
            "join",
            URL,
        ];
        if let Some(fingerprint) = explicit {
            args.extend(["--pin-fingerprint", fingerprint]);
        }
        run(dir, &args)
    };

    for (tag, pin) in [
        ("absent", None),
        ("url-mismatch", Some((OTHER_URL, HOST, FINGERPRINT))),
        ("host-mismatch", Some((URL, OTHER_HOST, FINGERPRINT))),
    ] {
        let dir = scratch(&format!("join-pin-{tag}"));
        handoff(&dir);
        if let Some((url, host, fingerprint)) = pin {
            add(&dir, url, host, fingerprint);
        }
        let output = join(&dir, None);
        assert_eq!(output.status.code(), Some(64), "{tag}: {}", stderr(&output));
        assert!(
            stderr(&output).contains("exact local pin"),
            "{tag}: {}",
            stderr(&output)
        );
    }

    let mismatch = scratch("join-pin-fingerprint-mismatch");
    handoff(&mismatch);
    add(&mismatch, URL, HOST, OTHER_FINGERPRINT);
    let output = join(&mismatch, None);
    assert_eq!(output.status.code(), Some(64), "{}", stderr(&output));
    assert!(stderr(&output).contains("differs from the invitation"));

    let exact = scratch("join-pin-exact");
    handoff(&exact);
    add(&exact, URL, HOST, FINGERPRINT);
    let output = join(&exact, None);
    assert_eq!(output.status.code(), Some(69), "{}", stderr(&output));

    // Choice 3A is an OR: an explicitly supplied out-of-band fingerprint is authoritative for
    // this invocation. It neither changes nor implicitly replaces a conflicting local pin.
    let explicit = scratch("join-pin-explicit");
    handoff(&explicit);
    add(&explicit, URL, HOST, OTHER_FINGERPRINT);
    let before = std::fs::read(explicit.join("host-pins.json")).expect("the pin store reads");
    let output = join(&explicit, Some(FINGERPRINT));
    assert_eq!(output.status.code(), Some(69), "{}", stderr(&output));
    assert_eq!(
        std::fs::read(explicit.join("host-pins.json")).expect("the pin store reads"),
        before,
        "join records no pin implicitly"
    );
}

#[test]
fn secret_bearing_json_errors_never_repeat_the_secret() {
    let dir = scratch("secret-json-error");
    let handoff = dir.join("invitation.json");
    let secret = "secret-field-op-token-never-print-this";
    std::fs::write(&handoff, format!("{{\"{secret}\":true}}"))
        .expect("the malformed handoff writes");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&handoff, std::fs::Permissions::from_mode(0o600))
            .expect("the handoff is private");
    }
    let output = run(
        &dir,
        &[
            "--host-endpoint",
            "https://127.0.0.1:1",
            "--token-file",
            "invitation.json",
            "host",
            "members",
            "join",
            "https://127.0.0.1:1",
            "--pin-fingerprint",
            "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        ],
    );
    let why = stderr(&output);
    assert_eq!(output.status.code(), Some(64), "{why}");
    assert!(!why.contains(secret), "{why}");
    assert!(why.contains("invalid invitation handoff JSON"), "{why}");
    assert!(why.contains("line") && why.contains("column"), "{why}");
}

/// TC-1: the client key may be a reference in the configuration, `env:NAME` or `file:PATH`, never
/// both a reference and a file, and never anything else.
#[test]
fn a_key_reference_names_a_variable_or_a_file() {
    let dir = scratch("key-ref");
    let with = |reference: &str, extra: &[(&str, &str)]| {
        let mut command = Command::new(env!("CARGO_BIN_EXE_permguard"));
        command
            .arg("-w")
            .arg(&dir)
            .args([
                "zones",
                "list",
                "--control-endpoint",
                "https://127.0.0.1:1",
                "--tls-cert-file",
                "cert.pem",
            ])
            .env("PERMGUARD_CONFIG", dir.join("cli-config.yml"))
            .env("PERMGUARD_TLS_KEY_REF", reference)
            .env("NO_COLOR", "1");
        for (name, value) in extra {
            command.env(name, value);
        }
        let output = command.output().expect("the binary runs");
        (output.status.code(), stderr(&output))
    };
    let (code, why) = with("vault:secret/key", &[]);
    assert_eq!(code, Some(64), "{why}");
    assert!(why.contains("env:NAME or file:PATH"), "{why}");
    let (code, why) = with("env:PERMGUARD_TEST_KEY_THAT_IS_UNSET", &[]);
    assert_eq!(code, Some(64), "{why}");
    assert!(why.contains("not set"), "{why}");
    // The flag (or its variable) is the most specific statement: it wins over a reference.
    let (code, why) = with("file:key.pem", &[("PERMGUARD_TLS_KEY_FILE", "other.pem")]);
    assert_ne!(code, Some(0), "{why}");
    assert!(
        why.contains("other.pem"),
        "the flag's file is the one read: {why}"
    );
    // Both in the configuration file is a mistake, not a precedence.
    std::fs::write(
        dir.join("cli-config.yml"),
        "tls:\n  keyFile: a.pem\n  keyRef: file:b.pem\n",
    )
    .expect("written");
    let output = run(
        &dir,
        &["zones", "list", "--control-endpoint", "https://127.0.0.1:1"],
    );
    assert_eq!(output.status.code(), Some(64), "{}", stderr(&output));
    assert!(
        stderr(&output).contains("named twice in the configuration"),
        "{}",
        stderr(&output)
    );
    std::fs::remove_file(dir.join("cli-config.yml")).expect("removed");
    // A variable holding something that is not a key: refused as TLS material, its contents
    // never printed.
    let (code, why) = with(
        "env:PERMGUARD_TEST_KEY_VALUE",
        &[("PERMGUARD_TEST_KEY_VALUE", "not-a-key-but-secret")],
    );
    assert_ne!(code, Some(0), "{why}");
    assert!(why.contains("not a PEM private key"), "{why}");
    assert!(!why.contains("not-a-key-but-secret"), "{why}");
}

/// TC-1: a verification that ran and did not pass exits 2, with its stable code.
#[test]
fn a_failed_verification_exits_two() {
    let dir = scratch("verification-two");
    std::fs::write(
        dir.join("producer-keys.json"),
        r#"{"keys":[{"kid":"unused","kty":"OKP","crv":"Ed25519","x":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","alg":"EdDSA","use":"sig"}]}"#,
    )
    .expect("the key set writes");
    // One record and no inclusion path: the export cannot account for it.
    std::fs::write(
        dir.join("events.json"),
        r#"{
          "format":"permguard.events.export.v1alpha1",
          "scope_binding":{"kind":"tenant","zone":"acme","ledger":"main"},
          "summary":{"scope":"acme/main","events":[],"next":"end","high_watermark":"end",
            "more":false,"coverage":{"contiguous":false,"examined":1,"scan_bounded":false}},
          "records":[{"kind":"request","seq":1,"id":"e-1","at":"2026-01-01T00:00:00Z"}],
          "envelopes":[],"inclusion":[]
        }"#,
    )
    .expect("the archive writes");
    let output = run(
        &dir,
        &[
            "events",
            "verify",
            "--file",
            "events.json",
            "--keys",
            "producer-keys.json",
            "-o",
            "json",
        ],
    );
    assert_eq!(output.status.code(), Some(2), "{}", stderr(&output));
    assert!(
        stderr(&output).contains("events_unverified"),
        "{}",
        stderr(&output)
    );
}

#[test]
fn host_identity_pins_are_canonical_private_idempotent_and_conflict_safe() {
    const HOST: &str = "0198f2aa-0000-7000-8000-000000000001";
    const FIRST: &str = "sha256:1111111111111111111111111111111111111111111111111111111111111111";
    const OTHER: &str = "sha256:2222222222222222222222222222222222222222222222222222222222222222";
    let dir = scratch("host-pins");
    let add = |fingerprint: &str| {
        run(
            &dir,
            &[
                "-o",
                "json",
                "host",
                "identity",
                "pin",
                "add",
                "https://COORDINATOR.EXAMPLE:9443",
                "--host-id",
                HOST,
                "--fingerprint",
                fingerprint,
            ],
        )
    };

    let added = add(FIRST);
    assert!(added.status.success(), "{}", stderr(&added));
    let path = dir.join("host-pins.json");
    let first = std::fs::read(&path).expect("the store was published");
    let parsed: serde_json::Value = serde_json::from_slice(&first).expect("the store is JSON");
    assert_eq!(parsed["version"], 1);
    assert_eq!(parsed["pins"][0]["url"], "https://coordinator.example:9443");
    assert_eq!(parsed["pins"][0]["host_id"], HOST);
    assert_eq!(parsed["pins"][0]["fingerprint"], FIRST);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        assert_eq!(
            std::fs::metadata(&path)
                .expect("the store metadata")
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }

    let replay = add(FIRST);
    assert!(replay.status.success(), "{}", stderr(&replay));
    assert_eq!(std::fs::read(&path).expect("the store reads"), first);

    let conflict = add(OTHER);
    assert_eq!(conflict.status.code(), Some(64), "{}", stderr(&conflict));
    assert!(stderr(&conflict).contains("different fingerprint"));
    assert_eq!(std::fs::read(&path).expect("the store reads"), first);

    let removed = run(
        &dir,
        &[
            "-o",
            "json",
            "host",
            "identity",
            "pin",
            "remove",
            "https://coordinator.example:9443",
            "--host-id",
            HOST,
        ],
    );
    assert!(removed.status.success(), "{}", stderr(&removed));
    let parsed: serde_json::Value =
        serde_json::from_str(&stdout(&removed)).expect("the answer is JSON");
    assert_eq!(parsed["pins"].as_array().expect("pins").len(), 0);
}
