// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! `streams verify <dir> --keys <file>` (WP-5.7c): a stream's directory copied off a volume,
//! checked offline through the command line of an app; an altered record exits `2`.

#![allow(clippy::expect_used)]

use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use clap::Parser;
use permguard_core::assurance::AssuranceProfile;
use permguard_core::authz::Resource;
use permguard_core::{BuildSettings, KeyManager as _, ProductIdentity};
use permguard_host::identity::{Identity, Suite, directories};
use permguard_host::keys::FileKeyProvider;
use permguard_host::keys::ring::{DATA_ATTEST, HOST_OPERATIONS, Policy, Ring};
use permguard_host::storage::volume::Volume;
use permguard_host::time::TimeGuard;
use permguard_server::{App, Cli, DefaultServerHost};
use permguard_std::audit::RecordingAuditSink;
use permguard_std::storage::MemoryStorage;
use permguard_stream::engine::{RecordCodec, Sealing, Streams};

fn scratch(tag: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!(
        "permguard-streams-verify-{tag}-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&path);
    path
}

/// Records as UTF-8 text: the batch check reads their bytes, never their meaning.
struct Text;

impl RecordCodec for Text {
    type Record = String;
    fn encode(&self, record: &String) -> Result<Vec<u8>, String> {
        Ok(record.as_bytes().to_vec())
    }
    fn decode(&self, bytes: &[u8]) -> Result<String, String> {
        String::from_utf8(bytes.to_vec()).map_err(|error| error.to_string())
    }
}

fn copy_tree(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).expect("a directory");
    for entry in std::fs::read_dir(from).expect("listed") {
        let entry = entry.expect("entry");
        let target = to.join(entry.file_name());
        if entry.file_type().expect("a type").is_dir() {
            copy_tree(&entry.path(), &target);
        } else {
            std::fs::copy(entry.path(), target).expect("copied");
        }
    }
}

/// A decision stream of six records sealed two a batch under `data.attest`, copied off its
/// volume: answers the copy and the `data.attest` keys written beside it.
fn sealed_stream(tag: &str) -> (PathBuf, PathBuf) {
    let root = scratch(tag);
    let volume = Volume::claim(&root, AssuranceProfile::Development).expect("claimed");
    let time = Arc::new(TimeGuard::system(Duration::from_secs(30)));
    let identity = Arc::new(
        Identity::provision(
            &volume,
            Arc::new(FileKeyProvider::new(
                directories(&volume).expect("the identity directory").1,
            )),
            Suite::Ed25519Sha256V1,
            permguard_host::authz::store::now(),
            permguard_host::authz::store::now() * 1000,
        )
        .expect("provisioned"),
    );
    let ring = |id: &'static str| {
        let ring = Arc::new(
            Ring::open(
                &volume,
                id,
                Suite::Ed25519Sha256V1,
                Policy {
                    publish_ahead: Duration::from_secs(600),
                    rotate_every: Duration::from_secs(3600),
                    retain: Duration::from_secs(7200),
                },
                Arc::clone(&time),
            )
            .expect("the ring opens")
            .with_binder(identity.clone()),
        );
        ring.maintain().expect("the first key");
        ring
    };
    let operations = ring(HOST_OPERATIONS);
    let attest = ring(DATA_ATTEST);
    let producer = Streams::open(&volume, &identity, operations, Arc::clone(&time))
        .expect("the engine opens")
        .register_producer(permguard_decisions::stream::descriptor(), Text)
        .expect("registered")
        .with_signer(Arc::clone(&attest))
        .expect("the descriptor's ring");
    let ledger = Resource::ledger("data", "zone-a", "ledger-1");
    for at in 0..6 {
        producer
            .append(&ledger, &format!("r{at}"))
            .expect("appended");
    }
    while let Sealing::Sealed { .. } = producer.seal(&ledger, 2).expect("sealed") {}
    let streams = root
        .join("host")
        .join("streams")
        .join("data")
        .join("decisions")
        .join("1")
        .join("producer");
    let component = std::fs::read_dir(&streams)
        .expect("listed")
        .next()
        .expect("one resource")
        .expect("entry")
        .path();
    let stream = std::fs::read_dir(&component)
        .expect("listed")
        .next()
        .expect("one producer")
        .expect("entry")
        .path();
    let copy = root.join("copy");
    copy_tree(&stream, &copy);
    let keys = root.join("data-attest.json");
    std::fs::write(&keys, attest.export_document().expect("the ring exports")).expect("written");
    (copy, keys)
}

fn app() -> App {
    App::new(
        ProductIdentity::new("demo-x", "Demo X", "A tagline", "Demo X CLI", "<art>"),
        BuildSettings::new("9.9.9", "2026", "Test Holder"),
        Box::new(DefaultServerHost::new()),
        Box::new(MemoryStorage::new()),
        Box::new(RecordingAuditSink::new()),
    )
}

async fn verify(directory: &Path, keys: &Path) -> (anyhow::Result<()>, String) {
    let action = Cli::try_parse_from([
        "demo-x".to_owned(),
        "streams".to_owned(),
        "verify".to_owned(),
        directory.display().to_string(),
        "--keys".to_owned(),
        keys.display().to_string(),
    ])
    .expect("the command parses")
    .action()
    .expect("an action");
    let mut out = Vec::new();
    let result = app().dispatch_to(&action, &mut out).await;
    (result, String::from_utf8(out).expect("text"))
}

/// WP-5.7c: a stream copied off its volume verifies under its ring's keys; an altered record
/// is a completed negative check, exit `2`; keys that cannot be read are exit `1`.
#[tokio::test]
async fn an_altered_record_in_a_copied_stream_exits_two() {
    let (copy, keys) = sealed_stream("sound");
    let (result, report) = verify(&copy, &keys).await;
    result.expect("verified");
    assert!(
        report.contains("3 batch(es), 6 record(s) checked"),
        "{report}"
    );
    assert!(report.contains("verified:"), "{report}");

    let batches = std::fs::read_dir(copy.join("batches"))
        .expect("listed")
        .next()
        .expect("one run")
        .expect("entry")
        .path();
    let file = batches.join("3-4.jws");
    let text = std::fs::read_to_string(&file).expect("the batch");
    let at = text.find("\"records\"").expect("records") + 15;
    let mut bytes = text.into_bytes();
    bytes[at] = if bytes[at] == b'A' { b'B' } else { b'A' };
    std::fs::write(&file, bytes).expect("altered");
    let (result, report) = verify(&copy, &keys).await;
    let failed = result.expect_err("an altered record");
    assert_eq!(
        permguard_server::app::exit_code_of(&failed),
        ExitCode::from(2)
    );
    assert!(report.contains("NOT verified"), "{report}");

    let unreadable = copy.join("no-such-keys.json");
    let (result, _) = verify(&copy, &unreadable).await;
    let failed = result.expect_err("no keys");
    assert_eq!(
        permguard_server::app::exit_code_of(&failed),
        ExitCode::FAILURE
    );
}
