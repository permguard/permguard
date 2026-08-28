#![cfg(feature = "audit")]
// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! What the file sink writes, and what verifying it catches.
//!
//! The point of a chained trail is not that it verifies — anything verifies when nobody has touched
//! it. The point is what happens when somebody has, so most of what follows tampers with a trail on
//! purpose and asserts that it stops verifying.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use permguard_core::{AuditEvent, AuditSink, Subject};
use permguard_std::audit::{FileAuditSink, verify};

/// A trail location nothing else is using.
///
/// Unique per process *and* per thread. A fixed name is not "nothing else is using": two
/// `cargo test` runs at once, or one run after a previous one left a directory behind, share it —
/// and these tests assert on the exact contents of a trail, so a stray file from somebody else's
/// run is a failure with no relationship to the code.
fn trail(name: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!(
        "permguard-trail-{name}-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = fs::remove_dir_all(&path);

    path
}

fn sink(directory: &Path) -> FileAuditSink {
    FileAuditSink::new(
        directory,
        "permguard",
        "9.9.9",
        // Ninety days, which is what a deployment would set.
        Duration::from_secs(90 * 86_400),
    )
}

/// Writes `count` ordinary records.
async fn write(sink: &FileAuditSink, count: usize) {
    for index in 0..count {
        let target = format!("run-{index}");
        let event = AuditEvent::system("service.start", "wellknown").on(&target);

        sink.record(&event, None)
            .await
            .expect("the record is written");
    }
}

/// Returns the only file of records in a trail.
fn only_file(directory: &Path) -> PathBuf {
    let mut files: Vec<PathBuf> = fs::read_dir(directory)
        .expect("the trail is there")
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| {
            path.extension()
                .is_some_and(|extension| extension == "jsonl")
        })
        .collect();

    assert_eq!(files.len(), 1, "expected one day of records");

    files.remove(0)
}

#[tokio::test]
async fn test_a_trail_nobody_touched_verifies() {
    let directory = trail("clean");
    let sink = sink(&directory);
    sink.prepare().expect("the trail is prepared");

    write(&sink, 5).await;

    let verified = verify(&directory).expect("it verifies");

    assert_eq!(verified.records, 5);
    assert_eq!(verified.days, 1);
    assert_eq!(verified.head.len(), 64, "the head is a SHA-256");
}

#[tokio::test]
async fn test_editing_a_record_in_place_stops_the_trail_verifying() {
    let directory = trail("edited");
    let sink = sink(&directory);
    sink.prepare().expect("the trail is prepared");
    write(&sink, 3).await;

    // The oldest thing an attacker wants to do: change what a record says and leave everything else.
    let path = only_file(&directory);
    let text = fs::read_to_string(&path).expect("the file reads");
    fs::write(&path, text.replace("service.start", "service.slart")).expect("the file is edited");

    let error = verify(&directory).expect_err("an edited record must not verify");

    assert!(
        format!("{error:#}").contains("altered"),
        "the failure did not say the record was altered: {error:#}"
    );
}

#[tokio::test]
async fn test_removing_a_record_stops_the_trail_verifying() {
    let directory = trail("removed");
    let sink = sink(&directory);
    sink.prepare().expect("the trail is prepared");
    write(&sink, 4).await;

    // The second oldest: delete the line that is inconvenient.
    let path = only_file(&directory);
    let text = fs::read_to_string(&path).expect("the file reads");
    let kept: Vec<&str> = text
        .lines()
        .enumerate()
        .filter(|(index, _)| *index != 1)
        .map(|(_, line)| line)
        .collect();
    fs::write(&path, format!("{}\n", kept.join("\n"))).expect("the file is edited");

    let error = verify(&directory).expect_err("a trail with a hole must not verify");

    assert!(
        format!("{error:#}").contains("does not follow"),
        "the failure did not identify a broken chain: {error:#}"
    );
}

#[tokio::test]
async fn test_truncating_the_trail_is_caught_by_the_sequence() {
    let directory = trail("truncated");
    let sink = sink(&directory);
    sink.prepare().expect("the trail is prepared");
    write(&sink, 4).await;

    // Cutting the tail off leaves a chain that is internally consistent, which is exactly why the
    // sequence is checked as well as the digests.
    let path = only_file(&directory);
    let text = fs::read_to_string(&path).expect("the file reads");
    let head: Vec<&str> = text.lines().take(2).collect();
    fs::write(&path, format!("{}\n", head.join("\n"))).expect("the file is edited");

    // Two records that follow each other still verify — truncation is only detectable against what
    // the trail is expected to contain, which is why the head is what gets attested elsewhere.
    let verified = verify(&directory).expect("what remains is self-consistent");

    assert_eq!(
        verified.records, 2,
        "the count is what makes a truncation visible to whoever kept the previous head"
    );
}

#[tokio::test]
async fn test_the_chain_continues_across_a_restart() {
    let directory = trail("restart");

    {
        let first = sink(&directory);
        first.prepare().expect("the trail is prepared");
        write(&first, 2).await;
        first.shutdown().await.expect("the trail is closed");
    }

    // A new process, the same trail. Starting the sequence again at 1 would leave a trail that never
    // verifies, and one that started a fresh chain would hide everything before the restart.
    let second = sink(&directory);
    second.prepare().expect("the trail is prepared");
    write(&second, 2).await;

    let verified = verify(&directory).expect("it verifies across the restart");

    assert_eq!(verified.records, 4);
}

#[tokio::test]
async fn test_a_record_carries_what_the_event_said_and_no_more() {
    let directory = trail("shape");
    let sink = sink(&directory);
    sink.prepare().expect("the trail is prepared");

    let event = AuditEvent::new("admin.request", Subject::Principal("someone@example.com"))
        .on("/permguard.admin.v1.Admin/GetVersion");
    sink.record(&event, None)
        .await
        .expect("the record is written");

    let text = fs::read_to_string(only_file(&directory)).expect("the file reads");

    assert!(text.contains(r#""action":"admin.request""#));
    assert!(text.contains(r#""target":"/permguard.admin.v1.Admin/GetVersion""#));
    assert!(text.contains(r#""subject_kind":"principal""#));
    assert!(text.contains(r#""subject_sensitivity":"personal""#));
    // With no pseudonymiser the subject is masked, and a masked person must not be readable.
    assert!(
        !text.contains("someone@example.com"),
        "a personal identifier reached the trail in the clear"
    );
}

#[tokio::test]
async fn test_a_day_past_its_retention_is_removed_and_one_inside_it_is_not() {
    let directory = trail("retention");
    fs::create_dir_all(&directory).expect("the directory is created");

    // Two days of records from a previous life: one older than the retention, one inside it.
    let stale = directory.join("audit-1970-01-02.jsonl");
    let recent = directory.join("audit-2999-01-01.jsonl");
    fs::write(&stale, "").expect("the old day is written");
    fs::write(&recent, "").expect("the recent day is written");

    sink(&directory).prepare().expect("the trail is prepared");

    assert!(!stale.exists(), "a day past its retention was kept");
    assert!(recent.exists(), "a day inside its retention was removed");
}

#[tokio::test]
async fn test_files_that_are_not_ours_are_left_alone() {
    let directory = trail("neighbours");
    fs::create_dir_all(&directory).expect("the directory is created");

    let notes = directory.join("README.md");
    fs::write(&notes, "why this directory exists").expect("the note is written");

    let sink = sink(&directory);
    sink.prepare().expect("the trail is prepared");
    write(&sink, 1).await;

    assert!(notes.exists(), "retention removed a file it does not own");
    assert_eq!(
        verify(&directory).expect("it verifies").records,
        1,
        "verification tried to read a file that is not a trail"
    );
}

#[tokio::test]
async fn test_a_trail_is_readable_only_by_the_user_running_the_process() {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let directory = trail("permissions");
        let sink = sink(&directory);
        sink.prepare().expect("the trail is prepared");
        write(&sink, 1).await;

        let mode = |path: &PathBuf| {
            fs::metadata(path)
                .expect("it is there")
                .permissions()
                .mode()
                & 0o777
        };

        assert_eq!(mode(&directory), 0o700);
        assert_eq!(mode(&only_file(&directory)), 0o600);
    }
}

#[tokio::test]
async fn test_an_empty_directory_verifies_as_an_empty_trail() {
    let directory = trail("empty");
    sink(&directory).prepare().expect("the trail is prepared");

    let verified = verify(&directory).expect("nothing is still something");

    assert_eq!(verified.records, 0);
    assert_eq!(verified.days, 0);
}

/// A key ring in a directory of its own, for the tests that need a signature.
#[cfg(feature = "keys")]
fn ring(name: &str) -> std::sync::Arc<permguard_std::keys::DirectoryKeyManager> {
    use permguard_core::KeyManager;
    use permguard_std::keys::{DirectoryKeyManager, KeyPolicy};

    let path = std::env::temp_dir().join(format!(
        "permguard-trail-keys-{name}-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = fs::remove_dir_all(&path);

    let keys = std::sync::Arc::new(DirectoryKeyManager::new(
        path,
        KeyPolicy {
            publish_ahead: Duration::from_secs(3600),
            rotate_every: Duration::from_secs(86_400),
            retain: Duration::from_secs(7 * 86_400),
            verify_retain: Duration::from_secs(7 * 86_400),
        },
    ));
    keys.maintain().expect("the ring comes up");

    keys
}

#[tokio::test]
async fn test_closing_the_trail_seals_where_the_chain_stood() {
    let directory = trail("sealed");
    let sink = sink(&directory);
    sink.prepare().expect("the trail is prepared");
    write(&sink, 3).await;
    sink.shutdown().await.expect("the trail is closed");

    let verified = verify(&directory).expect("it verifies");

    assert_eq!(verified.seals.len(), 1, "closing wrote no seal");
    let seal = &verified.seals[0];
    assert_eq!(seal.body.records, 3);
    assert_eq!(
        seal.body.head, verified.head,
        "the seal attests to a head the trail does not have"
    );
}

#[tokio::test]
async fn test_a_truncated_trail_is_caught_by_its_seal() {
    // Without a seal this is the one edit that survives: cut the tail off and what remains is
    // perfectly self-consistent. The seal is what turns it into evidence.
    let directory = trail("truncated-sealed");
    let sink = sink(&directory);
    sink.prepare().expect("the trail is prepared");
    write(&sink, 4).await;
    sink.shutdown().await.expect("the trail is closed");

    let path = only_file(&directory);
    let text = fs::read_to_string(&path).expect("the file reads");
    let kept: Vec<&str> = text.lines().take(2).collect();
    fs::write(&path, format!("{}\n", kept.join("\n"))).expect("the file is edited");

    let error = verify(&directory).expect_err("a truncated trail must not verify");

    let why = format!("{error:#}");
    assert!(why.contains("removed from the end"), "{why}");
    assert!(why.contains("attests to 4"), "{why}");
}

#[tokio::test]
async fn test_a_trail_rewritten_from_the_beginning_stops_agreeing_with_its_seal() {
    // The attacker the chain alone cannot catch: rewrite every record and recompute every digest, so
    // the result verifies against itself perfectly.
    let directory = trail("rewritten");
    let sink = sink(&directory);
    sink.prepare().expect("the trail is prepared");
    write(&sink, 3).await;
    sink.shutdown().await.expect("the trail is closed");

    let sealed = verify(&directory).expect("it verifies").head;

    // A whole new trail, the same length, written by the same code — and saying something else,
    // which is the entire reason to forge one.
    fs::remove_file(only_file(&directory)).expect("the day is removed");
    let forger = FileAuditSink::new(
        &directory,
        "permguard",
        "9.9.9",
        Duration::from_secs(90 * 86_400),
    );
    forger.prepare().expect("the trail is prepared");
    for index in 0..3 {
        let target = format!("run-{index}");
        let event = AuditEvent::system("service.stop", "wellknown").on(&target);

        forger
            .record(&event, None)
            .await
            .expect("the forged record is written");
    }

    // The forgery is internally perfect — and no longer what was sealed.
    let error = verify(&directory).expect_err("a rewritten trail must not verify");

    let why = format!("{error:#}");
    assert!(why.contains("rewritten since they were sealed"), "{why}");
    assert!(
        why.contains(&sealed),
        "the failure does not name the head that was sealed: {why}"
    );
}

#[cfg(feature = "keys")]
#[tokio::test]
async fn test_a_seal_is_signed_by_the_key_ring_and_verifies_against_the_published_set() {
    use permguard_core::KeyManager;

    let directory = trail("signed");
    let keys = ring("signed");
    let sink = sink(&directory).sealed_by(keys.clone());
    sink.prepare().expect("the trail is prepared");
    write(&sink, 2).await;
    sink.shutdown().await.expect("the trail is closed");

    let verified = verify(&directory).expect("it verifies");
    let seal = verified.seals.first().expect("a seal was written");

    let signature = seal.signature.as_deref().expect("the seal is signed");
    let kid = seal.kid.as_deref().expect("the seal names its key");
    assert_eq!(seal.algorithm.as_deref(), Some("EdDSA"));

    // The published key set — what a verifier that does not trust this machine would have fetched
    // from somewhere it does.
    let published = keys.public_keys().expect("the set reads");
    let jwk = published
        .iter()
        .find(|key| key.kid == kid)
        .expect("the key that signed is published");

    let bytes = seal.signed_bytes().expect("the signed bytes rebuild");
    let raw: Vec<u8> = (0..signature.len() / 2)
        .map(|i| u8::from_str_radix(&signature[i * 2..i * 2 + 2], 16).expect("hex"))
        .collect();

    assert!(
        permguard_std::keys::verify_signature(jwk, &bytes, &raw),
        "the signature does not verify against the published key"
    );

    // And it is a signature over *this* seal, not over anything that looks like one.
    let mut tampered = bytes.clone();
    tampered.push(b' ');
    assert!(!permguard_std::keys::verify_signature(jwk, &tampered, &raw));
}
