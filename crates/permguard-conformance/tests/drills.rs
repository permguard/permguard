// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! WP-7.7: the restore and split-brain drills run on a schedule, and every release carries their
//! records.
//!
//! The workflows are read as data: the `drills` workflow runs both drills every week, read-only,
//! and uploads what each recorded; the release pipeline runs them against the release, never
//! blocking it, and a job that compiles nothing attaches the records or the note saying why there
//! is none. A drill dropped from either fails here, not in a release that silently stopped running
//! it.

#![allow(clippy::expect_used, clippy::panic)]

use std::path::{Path, PathBuf};

use serde_norway::Value;

fn repository() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn workflow(name: &str) -> Value {
    let path = repository().join(".github/workflows").join(name);
    serde_norway::from_str(&std::fs::read_to_string(&path).expect("the workflow is readable"))
        .expect("the workflow is YAML")
}

fn job<'a>(workflow: &'a Value, name: &str) -> &'a Value {
    workflow["jobs"]
        .get(name)
        .unwrap_or_else(|| panic!("no job `{name}`"))
}

/// Every `run` script of a job, joined.
fn scripts(job: &Value) -> String {
    job["steps"]
        .as_sequence()
        .expect("steps")
        .iter()
        .filter_map(|step| step.get("run").and_then(Value::as_str))
        .collect::<Vec<_>>()
        .join("\n")
}

/// Every path a job's `upload-artifact` steps upload, joined.
fn uploads(job: &Value) -> String {
    job["steps"]
        .as_sequence()
        .expect("steps")
        .iter()
        .filter(|step| {
            step.get("uses")
                .and_then(Value::as_str)
                .is_some_and(|uses| uses.starts_with("actions/upload-artifact@"))
        })
        .filter_map(|step| step["with"].get("path").and_then(Value::as_str))
        .collect::<Vec<_>>()
        .join("\n")
}

/// Whether a permission set grants any write: a map with one `write`, or `write-all`.
fn grants_write(permissions: Option<&Value>) -> bool {
    match permissions {
        Some(Value::String(all)) => all == "write-all",
        Some(Value::Mapping(permissions)) => permissions
            .values()
            .any(|level| level.as_str() == Some("write")),
        _ => false,
    }
}

/// Whether `job` may write: its own permissions, or the workflow's when it declares none.
fn writes(workflow: &Value, job: &Value) -> bool {
    match job.get("permissions") {
        Some(own) => grants_write(Some(own)),
        None => grants_write(workflow.get("permissions")),
    }
}

#[test]
fn test_the_drills_run_every_week_and_record_what_they_proved() {
    let drills = workflow("drills.yml");
    let on = &drills["on"];
    assert!(
        on["schedule"]
            .as_sequence()
            .is_some_and(|schedule| !schedule.is_empty()),
        "the drills run on a schedule"
    );
    assert!(
        on.get("workflow_dispatch").is_some(),
        "and by hand, on a bad day"
    );

    let restore = job(&drills, "restore");
    assert!(
        scripts(restore).contains("scripts/drill-restore.sh drill-restore.json"),
        "{}",
        scripts(restore)
    );
    assert!(uploads(restore).contains("drill-restore.json"));

    let split_brain = job(&drills, "split-brain");
    let run = scripts(split_brain);
    assert!(
        run.contains("scripts/drill-split-brain.sh") && run.contains("drill-split-brain.json"),
        "{run}"
    );
    assert!(
        run.contains("scripts/chart-takeover.sh"),
        "the split-brain drill also runs where the volume is attached by a cluster:\n{run}"
    );
    assert!(uploads(split_brain).contains("drill-split-brain.json"));
    assert!(uploads(split_brain).contains("takeover-qualification.json"));

    for (name, job) in drills["jobs"].as_mapping().expect("jobs") {
        assert!(
            !writes(&drills, job),
            "{name:?} compiles: it must not hold a token that may write"
        );
    }
}

#[test]
fn test_a_release_is_drilled_and_carries_the_records() {
    let release = workflow("release-pipeline.yml");
    let drills = job(&release, "drills");
    assert_eq!(
        drills["needs"],
        serde_norway::from_str::<Value>("[build]").expect("YAML"),
        "the drills run against the published release, so after it is built"
    );
    let run = scripts(drills);
    assert!(
        run.contains("gh release download") && run.contains("permguard_all_in_one_Linux_x86_64"),
        "the split-brain drill runs the server the release published:\n{run}"
    );
    assert!(
        run.contains("scripts/drill-split-brain.sh ./permguard-all-in-one drill-split-brain.json"),
        "{run}"
    );
    assert!(
        run.contains("scripts/drill-restore.sh drill-restore.json"),
        "{run}"
    );
    assert!(
        !writes(&release, drills),
        "the drills build the lab image: they must not hold a token that may write"
    );
    assert_eq!(
        drills["continue-on-error"].as_bool(),
        Some(true),
        "the drills report on a published release and never block it"
    );

    let publish = job(&release, "publish-drills");
    assert_eq!(
        publish["needs"],
        serde_norway::from_str::<Value>("[build, drills]").expect("YAML")
    );
    assert!(
        publish["if"]
            .as_str()
            .is_some_and(|condition| condition.contains("always()")),
        "the records, or the notes saying why there are none, are attached whatever the drills did"
    );
    assert!(
        writes(&release, publish),
        "attaching the records needs `contents: write`"
    );
    let attach = scripts(publish);
    assert!(
        attach.contains("gh release upload")
            && attach.contains("drill-split-brain")
            && attach.contains("drill-restore")
            && attach.contains(".txt"),
        "{attach}"
    );
    assert!(
        !attach.contains("cargo") && !attach.contains("docker"),
        "the job that may write compiles nothing"
    );
}

/// The scripts the workflows run exist and are executable.
#[test]
fn test_the_drill_scripts_are_executable() {
    for script in [
        "scripts/drill-restore.sh",
        "scripts/drill-split-brain.sh",
        "scripts/chart-takeover.sh",
    ] {
        let path = repository().join(script);
        let metadata = std::fs::metadata(&path).unwrap_or_else(|_| panic!("no {script}"));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            assert!(
                metadata.permissions().mode() & 0o111 != 0,
                "{script} is not executable"
            );
        }
        #[cfg(not(unix))]
        let _ = metadata;
    }
}
