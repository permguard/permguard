// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The release scripts, run as the release builder runs them, against fixtures and a stand-in `gh`.
//!
//! | Script                       | Proven here                                                                          |
//! | ---------------------------- | ------------------------------------------------------------------------------------ |
//! | `scripts/verify-provenance.sh` | both phases pass on a complete release and name the builder; an empty, malformed or short listing fails; an image is verified once per digest; a slow attestation is retried, a missing one fails |
//! | `scripts/image-digests.sh` | every image and tag of the configuration, both registries, `latest` included, as `<hex>  <image>:<tag>` — the form `actions/attest` reads; a `sha256:` prefix never reaches it |
//! | `scripts/extract-shipped.sh` | the 16 published Linux and Windows archives become the layout the build stages; a stray file fails |
//! | `scripts/compare-rebuild.sh` | identical builds read `reproducible: yes`; one altered byte reads `reproducible: no` and exits 3 |
//! | `scripts/evidence-manifest.sh`, `scripts/verify-evidence.sh` | a complete release pins every file and verifies, its attestation first; a changed, missing or unnamed file and an incomplete gate are refused |
//!
//! Each script runs under `bash`, whichever the machine has: the release runners carry bash 5, a
//! Mac carries 3.2, and the scripts are written for both.

#![cfg(unix)]
#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const BINARIES: [&str; 4] = [
    "permguard",
    "permguard-all-in-one",
    "permguard-control-plane",
    "permguard-data-plane",
];
const ARCHIVE_IDS: [&str; 4] = [
    "permguard_cli",
    "permguard_all_in_one",
    "permguard_control_plane",
    "permguard_data_plane",
];
const IMAGES: [&str; 8] = [
    "ghcr.io/permguard/permguard/cli",
    "ghcr.io/permguard/permguard/all-in-one",
    "ghcr.io/permguard/permguard/control-plane",
    "ghcr.io/permguard/permguard/data-plane",
    "permguard/cli",
    "permguard/all-in-one",
    "permguard/control-plane",
    "permguard/data-plane",
];

fn repository() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn scratch(tag: &str) -> PathBuf {
    let directory = std::env::temp_dir().join(format!(
        "pg-release-scripts-{tag}-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&directory);
    std::fs::create_dir_all(&directory).expect("the scratch directory is created");

    directory
}

fn write_executable(path: &Path, text: &str) {
    std::fs::write(path, text).expect("the script is written");
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755))
        .expect("the script is made executable");
}

/// A stand-in `gh`: it logs its arguments, fails its first `failures` calls as an attestation not
/// yet served would, and then answers what `gh attestation verify --format json` answers.
fn stand_in_gh(root: &Path, failures: u32) -> PathBuf {
    let bin = root.join("bin");
    std::fs::create_dir_all(&bin).expect("the bin directory is created");
    write_executable(
        &bin.join("gh"),
        &format!(
            r#"#!/bin/sh
printf '%s\n' "$*" >> "{log}"
count=$(cat "{count}" 2>/dev/null || echo 0)
count=$((count + 1))
echo "$count" > "{count}"
if [ "$count" -le {failures} ]; then
    echo "no attestations found" >&2
    exit 1
fi
echo '[{{"verificationResult":{{"signature":{{"certificate":{{"buildSignerURI":"https://github.com/permguard/permguard/.github/workflows/release-build.yml@refs/tags/v1.2.3","sourceRepositoryURI":"https://github.com/permguard/permguard","sourceRepositoryRef":"refs/tags/v1.2.3","sourceRepositoryDigest":"0123abcd"}}}}}}}}]'
"#,
            log = root.join("gh.log").display(),
            count = root.join("gh.count").display(),
        ),
    );

    bin
}

fn run(script: &str, arguments: &[&str], path_prefix: Option<&Path>) -> Output {
    let mut command = Command::new("bash");
    command
        .arg(repository().join("scripts").join(script))
        .args(arguments)
        .env("GITHUB_REPOSITORY", "permguard/permguard")
        .env("GITHUB_REF_NAME", "v1.2.3")
        .env("GITHUB_SHA", "0123abcd")
        .env("VERIFY_PAUSE", "0");
    if let Some(prefix) = path_prefix {
        let path = std::env::var("PATH").unwrap_or_default();
        command.env("PATH", format!("{}:{path}", prefix.display()));
    }

    command.output().expect("bash runs the script")
}

fn text(output: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

fn digest(index: usize) -> String {
    format!("{index:064x}")
}

fn checksums(dist: &Path, files: usize) {
    let listing: String = (0..files)
        .map(|index| format!("{}  archive-{index}.tar.gz\n", digest(index)))
        .collect();
    std::fs::write(dist.join("checksums.txt"), listing).expect("checksums.txt is written");
}

fn digests(dist: &Path, images: &[&str]) {
    // Three tags of one image share its digest, as a release pushes them; the GHCR one carries the
    // `sha256:` prefix GoReleaser may write, the other not.
    let listing: String = images
        .iter()
        .enumerate()
        .flat_map(|(index, image)| {
            ["1.2.3", "1.2", "latest"]
                .into_iter()
                .map(move |tag| format!("sha256:{}  {image}:{tag}\n", digest(index)))
        })
        .collect();
    std::fs::write(dist.join("digests.txt"), listing).expect("digests.txt is written");
}

#[test]
fn test_both_provenance_phases_pass_on_a_complete_release_and_name_the_builder() {
    let root = scratch("complete");
    let bin = stand_in_gh(&root, 0);
    let dist = root.join("dist");
    std::fs::create_dir_all(&dist).expect("dist is created");
    checksums(&dist, 31);
    digests(&dist, &IMAGES);

    let files = run(
        "verify-provenance.sh",
        &["files", dist.to_str().unwrap()],
        Some(&bin),
    );
    assert!(files.status.success(), "{}", text(&files));
    assert!(text(&files).contains("31 files"), "{}", text(&files));
    let images = run(
        "verify-provenance.sh",
        &["images", dist.to_str().unwrap()],
        Some(&bin),
    );
    assert!(images.status.success(), "{}", text(&images));
    assert!(
        text(&images).contains("8 images"),
        "three tags of one image are one artifact: {}",
        text(&images)
    );

    let log = std::fs::read_to_string(root.join("gh.log")).expect("gh was called");
    assert_eq!(log.lines().count(), 39, "31 files and 8 images, each once");
    assert!(
        log.lines().all(|line| line
            .contains("--signer-workflow permguard/permguard/.github/workflows/release-build.yml")
            && line.contains("--source-ref refs/tags/v1.2.3")
            && line.contains("--source-digest 0123abcd")
            && line.contains("--deny-self-hosted-runners")),
        "every verification enforces the whole policy:\n{log}"
    );
    assert!(
        log.contains("oci://ghcr.io/permguard/permguard/cli@sha256:")
            && log.contains("oci://permguard/data-plane@sha256:"),
        "an image is verified by digest, without its tag:\n{log}"
    );
    let evidence =
        std::fs::read_to_string(dist.join("provenance-files.txt")).expect("the evidence is kept");
    assert!(evidence.contains(
        "builder: https://github.com/permguard/permguard/.github/workflows/release-build.yml"
    ));
}

#[test]
fn test_a_release_that_is_empty_malformed_or_short_is_not_verified() {
    let root = scratch("refused");
    let bin = stand_in_gh(&root, 0);
    let dist = root.join("dist");
    std::fs::create_dir_all(&dist).expect("dist is created");
    let dist_arg = dist.to_str().unwrap();

    std::fs::write(dist.join("checksums.txt"), "").expect("an empty listing");
    let empty = run("verify-provenance.sh", &["files", dist_arg], Some(&bin));
    assert!(!empty.status.success(), "an empty listing passed");

    std::fs::write(dist.join("checksums.txt"), "not a checksum line\n").expect("a bad line");
    let malformed = run("verify-provenance.sh", &["files", dist_arg], Some(&bin));
    assert!(!malformed.status.success(), "a malformed line passed");
    assert!(
        text(&malformed).contains("not `<sha256>  <name>`"),
        "{}",
        text(&malformed)
    );

    checksums(&dist, 23);
    let short = run("verify-provenance.sh", &["files", dist_arg], Some(&bin));
    assert!(!short.status.success(), "23 files passed");

    digests(&dist, &IMAGES[..6]);
    let six = run("verify-provenance.sh", &["images", dist_arg], Some(&bin));
    assert!(!six.status.success(), "six images passed: {}", text(&six));

    let unknown = run(
        "verify-provenance.sh",
        &["everything", dist_arg],
        Some(&bin),
    );
    assert!(!unknown.status.success(), "an unknown phase passed");
}

#[test]
fn test_an_attestation_not_yet_served_is_retried_and_a_missing_one_fails() {
    let root = scratch("retried");
    let bin = stand_in_gh(&root, 2);
    let dist = root.join("dist");
    std::fs::create_dir_all(&dist).expect("dist is created");
    checksums(&dist, 24);
    let late = run(
        "verify-provenance.sh",
        &["files", dist.to_str().unwrap()],
        Some(&bin),
    );
    assert!(
        late.status.success(),
        "two late answers failed the release: {}",
        text(&late)
    );

    let root = scratch("missing");
    let bin = stand_in_gh(&root, 1_000);
    let dist = root.join("dist");
    std::fs::create_dir_all(&dist).expect("dist is created");
    checksums(&dist, 24);
    let missing = run(
        "verify-provenance.sh",
        &["files", dist.to_str().unwrap()],
        Some(&bin),
    );
    assert!(!missing.status.success(), "a missing attestation passed");
    assert!(
        text(&missing).contains("after 3 attempts"),
        "{}",
        text(&missing)
    );
}

/// Builds the 16 Linux and Windows archives a release publishes, each holding one binary, the
/// files GoReleaser adds beside it, and returns the layout the build staged them from.
fn published(root: &Path) -> (PathBuf, PathBuf) {
    let archives = root.join("published");
    let staged = root.join("staged");
    std::fs::create_dir_all(&archives).expect("the archives directory is created");
    for (id, binary) in ARCHIVE_IDS.iter().zip(BINARIES) {
        for (os, os_title) in [("linux", "Linux"), ("windows", "Windows")] {
            for (arch, arch_title) in [("amd64", "x86_64"), ("arm64", "arm64")] {
                let contents = format!("{binary} for {os}_{arch}\n");
                let platform = staged.join(format!("{os}_{arch}"));
                std::fs::create_dir_all(&platform).expect("the platform directory is created");
                std::fs::write(platform.join(binary), &contents).expect("a staged binary");

                let work = root.join("work");
                let _ = std::fs::remove_dir_all(&work);
                std::fs::create_dir_all(&work).expect("the work directory is created");
                let member = if os == "windows" {
                    format!("{binary}.exe")
                } else {
                    binary.to_owned()
                };
                std::fs::write(work.join(&member), &contents).expect("an archived binary");
                std::fs::write(work.join("LICENSE"), "licence\n").expect("a licence");
                let name = format!("{id}_{os_title}_{arch_title}");
                let status = if os == "windows" {
                    Command::new("zip")
                        .current_dir(&work)
                        .args(["-q", archives.join(format!("{name}.zip")).to_str().unwrap()])
                        .args([member.as_str(), "LICENSE"])
                        .status()
                } else {
                    Command::new("tar")
                        .current_dir(&work)
                        .args([
                            "-czf",
                            archives.join(format!("{name}.tar.gz")).to_str().unwrap(),
                        ])
                        .args([member.as_str(), "LICENSE"])
                        .status()
                };
                assert!(status.expect("the archiver runs").success(), "{name}");
            }
        }
    }

    (archives, staged)
}

#[test]
fn test_published_archives_round_trip_into_a_reproducibility_verdict() {
    let root = scratch("round-trip");
    let (archives, staged) = published(&root);
    let shipped = root.join("shipped");

    let extracted = run(
        "extract-shipped.sh",
        &[archives.to_str().unwrap(), shipped.to_str().unwrap()],
        None,
    );
    assert!(extracted.status.success(), "{}", text(&extracted));
    assert_eq!(
        std::fs::read_to_string(shipped.join("windows_arm64/permguard-data-plane"))
            .expect("the Windows binary is staged without its extension"),
        "permguard-data-plane for windows_arm64\n"
    );

    let verdict = root.join("verdict.txt");
    let same = run(
        "compare-rebuild.sh",
        &[
            shipped.to_str().unwrap(),
            staged.to_str().unwrap(),
            verdict.to_str().unwrap(),
        ],
        None,
    );
    assert!(same.status.success(), "{}", text(&same));
    assert!(text(&same).contains("reproducible: yes"), "{}", text(&same));

    std::fs::write(staged.join("linux_arm64/permguard"), "altered\n").expect("one binary differs");
    let different = run(
        "compare-rebuild.sh",
        &[
            shipped.to_str().unwrap(),
            staged.to_str().unwrap(),
            verdict.to_str().unwrap(),
        ],
        None,
    );
    assert_eq!(different.status.code(), Some(3), "{}", text(&different));
    assert!(
        text(&different).contains("MISMATCH"),
        "{}",
        text(&different)
    );
    assert!(
        text(&different).contains("reproducible: no"),
        "{}",
        text(&different)
    );

    std::fs::write(archives.join("notes.txt"), "stray\n").expect("a stray file");
    let stray = run(
        "extract-shipped.sh",
        &[
            archives.to_str().unwrap(),
            root.join("again").to_str().unwrap(),
        ],
        None,
    );
    assert!(!stray.status.success(), "a stray file was skipped silently");
}

/// A release directory holding every piece of evidence the exit gate requires, each passing.
fn complete_evidence(directory: &Path) {
    std::fs::create_dir_all(directory).expect("the release directory");
    for name in ["permguard-benchmark.json", "traceability.json"] {
        std::fs::write(directory.join(name), r#"{"report": true}"#).expect("written");
    }
    std::fs::write(directory.join("permguard-gate.json"), r#"{"passed": true}"#).expect("written");
    for name in [
        "drill-split-brain.json",
        "drill-restore.json",
        "fuzz-release.json",
    ] {
        std::fs::write(directory.join(name), r#"{"result": "passed"}"#).expect("written");
    }
    std::fs::write(
        directory.join("reproducibility.txt"),
        "permguard 0123 0123\nreproducible: yes\n",
    )
    .expect("written");
    for name in [
        "checksums.txt",
        "provenance-files.json",
        "provenance-images.json",
        "permguard_cli_Linux_x86_64.tar.gz.sbom.json",
        "permguard_cli_Linux_x86_64.tar.gz",
    ] {
        std::fs::write(directory.join(name), name).expect("written");
    }
}

/// WP-7.13: the evidence manifest pins every file of the release to the commit and is complete only
/// when every piece of evidence is there and passed; the verifier recomputes every digest and fails
/// closed on a changed, missing or unnamed file and on an incomplete gate.
#[test]
fn the_evidence_manifest_pins_the_release_and_its_verification_fails_closed() {
    let root = scratch("evidence");
    let release = root.join("release");
    complete_evidence(&release);
    let made = run(
        "evidence-manifest.sh",
        &[release.to_str().expect("utf-8"), "v1.2.3", "0123abcd"],
        None,
    );
    assert!(made.status.success(), "{}", text(&made));
    let manifest: serde_json::Value = serde_json::from_slice(
        &std::fs::read(release.join("evidence-manifest.json")).expect("the manifest"),
    )
    .expect("JSON");
    assert_eq!(manifest["schema"], "permguard.evidence-manifest.v1");
    assert_eq!(manifest["commit"], "0123abcd");
    assert_eq!(manifest["complete"], true, "{manifest}");
    assert_eq!(
        manifest["artifacts"].as_array().expect("artifacts").len(),
        12
    );

    // The attestation of the manifest is checked first when a repository is named.
    let gh = stand_in_gh(&root, 0);
    let verified = run(
        "verify-evidence.sh",
        &[
            release.to_str().expect("utf-8"),
            "permguard/permguard",
            "v1.2.3",
        ],
        Some(&gh),
    );
    assert!(verified.status.success(), "{}", text(&verified));
    assert!(
        text(&verified).contains("\"verified\": true"),
        "{}",
        text(&verified)
    );
    let called = std::fs::read_to_string(root.join("gh.log")).expect("gh was called");
    assert!(
        called.contains("attestation verify")
            && called.contains(
                "--signer-workflow permguard/permguard/.github/workflows/release-pipeline.yml"
            )
            && called.contains("--source-ref refs/tags/v1.2.3")
            && called.contains("--deny-self-hosted-runners"),
        "the manifest is the release pipeline's own: {called}"
    );
    // An attestation that does not verify refuses the evidence before any digest is read.
    std::fs::remove_file(root.join("gh.count")).expect("reset");
    let unattested = run(
        "verify-evidence.sh",
        &[
            release.to_str().expect("utf-8"),
            "permguard/permguard",
            "v1.2.3",
        ],
        Some(&stand_in_gh(&root, 1)),
    );
    assert!(!unattested.status.success());
    assert!(
        text(&unattested).contains("attestation does not verify"),
        "{}",
        text(&unattested)
    );

    let verify = || {
        run(
            "verify-evidence.sh",
            &[
                release.to_str().expect("utf-8"),
                "permguard/permguard",
                "v1.2.3",
            ],
            Some(&gh),
        )
    };
    // Another release's tag: the manifest is not the one asked about.
    let other = run(
        "verify-evidence.sh",
        &[
            release.to_str().expect("utf-8"),
            "permguard/permguard",
            "v9.9.9",
        ],
        Some(&gh),
    );
    assert!(!other.status.success());
    assert!(
        text(&other).contains("is not a permguard.evidence-manifest.v1 of v9.9.9"),
        "{}",
        text(&other)
    );
    // The repository and the tag are required: nothing verifies unattested.
    let unnamed = run(
        "verify-evidence.sh",
        &[release.to_str().expect("utf-8")],
        Some(&gh),
    );
    assert!(!unnamed.status.success());
    // A manifest of another shape fails closed rather than reading as empty.
    let held = std::fs::read(release.join("evidence-manifest.json")).expect("the manifest");
    let shape: serde_json::Value = serde_json::from_slice(&held).expect("JSON");
    for (what, edit) in [
        (
            "only its schema",
            serde_json::json!({"schema": "permguard.evidence-manifest.v1", "tag": "v1.2.3"}),
        ),
        ("incomplete null", {
            let mut edited = shape.clone();
            edited["incomplete"] = serde_json::Value::Null;
            edited
        }),
        ("artifacts null", {
            let mut edited = shape.clone();
            edited["artifacts"] = serde_json::Value::Null;
            edited
        }),
        ("complete false", {
            let mut edited = shape.clone();
            edited["complete"] = serde_json::json!(false);
            edited
        }),
        ("a name outside the directory", {
            let mut edited = shape.clone();
            edited["artifacts"][0]["name"] = serde_json::json!("../checksums.txt");
            edited
        }),
    ] {
        std::fs::write(
            release.join("evidence-manifest.json"),
            serde_json::to_vec(&edit).expect("JSON"),
        )
        .expect("written");
        let refused = verify();
        assert!(!refused.status.success(), "{what}: {}", text(&refused));
        assert!(
            text(&refused).contains("is not a permguard.evidence-manifest.v1"),
            "{what}: {}",
            text(&refused)
        );
    }
    std::fs::write(release.join("evidence-manifest.json"), &held).expect("restored");
    assert!(verify().status.success());
    // One byte changed in a shipped file.
    let archive = release.join("permguard_cli_Linux_x86_64.tar.gz");
    std::fs::write(&archive, "altered").expect("altered");
    let refused = verify();
    assert!(!refused.status.success());
    assert!(
        text(&refused).contains("its digest changed"),
        "{}",
        text(&refused)
    );
    std::fs::write(&archive, "permguard_cli_Linux_x86_64.tar.gz").expect("restored");
    assert!(verify().status.success());

    // A file the manifest does not name.
    std::fs::write(release.join("added-later.bin"), "x").expect("written");
    let refused = verify();
    assert!(!refused.status.success());
    assert!(
        text(&refused).contains("not named by the manifest"),
        "{}",
        text(&refused)
    );
    std::fs::remove_file(release.join("added-later.bin")).expect("removed");

    // A file the manifest names, gone.
    std::fs::remove_file(release.join("checksums.txt")).expect("removed");
    let refused = verify();
    assert!(!refused.status.success());
    assert!(
        text(&refused).contains("checksums.txt: missing"),
        "{}",
        text(&refused)
    );
    let _ = std::fs::remove_dir_all(&root);
}

/// WP-7.13: a piece of evidence missing, replaced by its note, or not passed leaves the gate
/// incomplete; the manifest says which, and the verifier refuses it.
#[test]
fn an_incomplete_gate_is_named_in_the_manifest_and_refused_by_the_verifier() {
    let root = scratch("evidence-incomplete");
    let release = root.join("release");
    complete_evidence(&release);
    std::fs::remove_file(release.join("drill-restore.json")).expect("removed");
    std::fs::write(
        release.join("drill-restore.txt"),
        "the drill did not complete",
    )
    .expect("note");
    std::fs::write(release.join("fuzz-release.json"), r#"{"result": "failed"}"#).expect("failed");
    std::fs::write(release.join("permguard-gate.json"), r#"{"passed": false}"#).expect("failed");
    std::fs::remove_file(release.join("traceability.json")).expect("removed");
    std::fs::remove_file(release.join("permguard_cli_Linux_x86_64.tar.gz.sbom.json"))
        .expect("removed");
    std::fs::write(
        release.join("reproducibility.txt"),
        "reproducible: no — this release does not claim to be reproducible\n",
    )
    .expect("not reproducible");
    let made = run(
        "evidence-manifest.sh",
        &[release.to_str().expect("utf-8"), "v1.2.3", "0123abcd"],
        None,
    );
    assert!(
        made.status.success(),
        "the manifest is still written: {}",
        text(&made)
    );
    let manifest: serde_json::Value = serde_json::from_slice(
        &std::fs::read(release.join("evidence-manifest.json")).expect("the manifest"),
    )
    .expect("JSON");
    assert_eq!(manifest["complete"], false);
    let incomplete = manifest["incomplete"].to_string();
    for expected in [
        "drill-restore.json: not produced; drill-restore.txt says why",
        "fuzz-release.json: result is \\\"failed\\\"",
        "the serving gate did not pass",
        "traceability.json: missing",
        "no SBOM",
        "the independent rebuild did not reproduce the release",
    ] {
        assert!(incomplete.contains(expected), "{expected} in {incomplete}");
    }
    let refused = run(
        "verify-evidence.sh",
        &[
            release.to_str().expect("utf-8"),
            "permguard/permguard",
            "v1.2.3",
        ],
        Some(&stand_in_gh(&root, 0)),
    );
    assert!(!refused.status.success());
    assert!(
        text(&refused).contains("the gate is incomplete"),
        "{}",
        text(&refused)
    );
    let _ = std::fs::remove_dir_all(&root);
}

/// `scripts/image-digests.sh` writes the file `actions/attest` reads as `subject-checksums`: the
/// `sha256sum` form, a hex digest and the image reference, with no `sha256:` prefix — to the
/// attestation the prefix is an invalid digest, and it failed a release at its last step. Every
/// image and tag of `.goreleaser.yaml`, in both registries, `latest` included.
#[test]
fn test_the_image_digests_are_written_the_way_the_attestation_reads_them() {
    if Command::new("yq").arg("--version").output().is_err() {
        eprintln!("skipped: the script reads the configuration with yq, which this machine lacks");
        return;
    }
    let root = scratch("image-digests");
    let bin = root.join("bin");
    std::fs::create_dir_all(&bin).expect("the bin directory is created");
    // A stand-in `docker buildx imagetools inspect <ref> --format ...`: the registry answers the
    // manifest's digest, prefixed the way a registry prefixes it, one per reference.
    write_executable(
        &bin.join("docker"),
        r#"#!/bin/sh
printf '{"digest":"sha256:%s"}\n' "$(printf '%s' "$4" | shasum -a 256 | cut -d' ' -f1)"
"#,
    );
    let out = root.join("digests.txt");
    let configuration = repository().join(".goreleaser.yaml");
    let output = run(
        "image-digests.sh",
        &[
            "v1.2.3",
            out.to_str().expect("a path"),
            configuration.to_str().expect("a path"),
        ],
        Some(&bin),
    );
    assert!(output.status.success(), "{}", text(&output));

    let listing = std::fs::read_to_string(&out).expect("digests.txt is written");
    let lines: Vec<&str> = listing.lines().collect();
    for line in &lines {
        let (digest, reference) = line
            .split_once("  ")
            .expect("a line is `<sha256>  <image>:<tag>`");
        assert!(
            digest.len() == 64 && digest.chars().all(|c| c.is_ascii_hexdigit()),
            "hex only, no `sha256:` prefix: {line}"
        );
        assert!(!reference.contains(' '), "{line}");
    }
    // Four images in two registries, three tags each.
    assert_eq!(lines.len(), 24, "{listing}");
    for image in IMAGES {
        for tag in ["1.2.3", "1.2", "latest"] {
            assert!(
                lines
                    .iter()
                    .any(|line| line.ends_with(&format!("  {image}:{tag}"))),
                "{image}:{tag} in:\n{listing}"
            );
        }
    }
}
