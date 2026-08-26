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
