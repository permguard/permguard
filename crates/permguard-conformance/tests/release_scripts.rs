// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The release scripts, run as the release builder runs them, against fixtures and a stand-in `gh`.
//!
//! | Script                       | Proven here                                                                          |
//! | ---------------------------- | ------------------------------------------------------------------------------------ |
//! | `scripts/verify-provenance.sh` | both phases pass on a complete release and name the builder; an empty, malformed or short listing fails; an image is verified once per digest; a slow attestation is retried, a missing one fails |
//! | `scripts/extract-shipped.sh` | the 16 published Linux and Windows archives become the layout the build stages; a stray file fails |
//! | `scripts/compare-rebuild.sh` | identical builds read `reproducible: yes`; one altered byte reads `reproducible: no` and exits 3 |
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
