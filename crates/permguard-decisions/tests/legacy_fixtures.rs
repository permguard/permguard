// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! A decision spool as this release writes it, kept so that every later layout can prove it still
//! reads one.
//!
//! `tests/fixtures/legacy/v1/decision-spool` is a volume fragment written by the current code:
//! `STATE`, `RESERVE`, one segment with a marker and two decisions. In CI the fixture is copied aside and opened
//! by the current spool, which must recover the same three records. Setting
//! `PERMGUARD_CAPTURE_LEGACY_FIXTURES=1` rewrites the fixture from the current code instead; that is
//! done once per layout version and reviewed, never to make a failing test pass.
//!
//! The fixture is the v1 compatibility baseline: every later migration of this store must read it.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::fs;
use std::path::{Path, PathBuf};

use permguard_decisions::record::{
    ActionRef, Body, Build, Commitments, DecisionBody, GENESIS, Inputs, MarkerBody, Party, Reason,
    Record, Sampling, StoreRef, Stream, VERSION, digest_of,
};
use permguard_decisions::spool::{Bounds, Spool};

const FIXTURE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/legacy/v1/decision-spool"
);

fn scratch() -> PathBuf {
    let path = std::env::temp_dir().join(format!(
        "permguard-legacy-decision-spool-{}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&path);
    fs::create_dir_all(&path).expect("the scratch directory is created");
    path
}

fn copy_dir(from: &Path, to: &Path) {
    fs::create_dir_all(to).expect("the target directory is created");
    for entry in fs::read_dir(from).expect("the source directory is listed") {
        let entry = entry.expect("an entry is read");
        let target = to.join(entry.file_name());
        if entry.file_type().expect("a file type").is_dir() {
            copy_dir(&entry.path(), &target);
        } else {
            fs::copy(entry.path(), &target).expect("a file is copied");
        }
    }
}

fn build_info() -> Build {
    Build {
        version: "0.1.0".to_owned(),
        build: None,
        engines: None,
    }
}

/// A stream as a PDP opens one: a marker, then two decisions, one permit and one deny.
fn body(seq: u64) -> Body {
    if seq == 1 {
        return Body::Marker(Box::new(MarkerBody {
            predecessor: None,
            pdp: build_info(),
            sampling: Sampling {
                permits: "1.0".to_owned(),
            },
            commitments: Commitments {
                alg: "HMAC-SHA256".to_owned(),
                key_version: "v1".to_owned(),
            },
        }));
    }
    Body::Decision(Box::new(DecisionBody {
        id: format!("d-{seq}"),
        pdp: build_info(),
        store: StoreRef {
            zone: "zone-a".to_owned(),
            ledger: "ledger-a".to_owned(),
            commit: "sha256:ec1773bf".to_owned(),
            counter: 1,
            profile: "default".to_owned(),
        },
        subject: Party {
            kind: "User".to_owned(),
            id: "pseudo:v1:9f2c".to_owned(),
            properties: None,
        },
        resource: Party {
            kind: "Document".to_owned(),
            id: "budget".to_owned(),
            properties: None,
        },
        action: ActionRef {
            name: "read".to_owned(),
        },
        principal: None,
        inputs: Inputs::default(),
        decision: seq == 2,
        // Written before `outcome` existed: the legacy bytes carry no such member.
        outcome: None,
        causes: None,
        policies: vec!["policy-1".to_owned()],
        reason: Reason {
            code: if seq == 2 { "200" } else { "403" }.to_owned(),
        },
        trace: None,
        request_id: None,
        context: None,
        latency_us: 143,
        event: None,
    }))
}

fn build(directory: &Path) {
    let mut spool = Spool::open(directory, Bounds::default()).expect("the spool opens");
    let mut prev = GENESIS.to_owned();
    for seq in 1..=3 {
        let record = Record {
            v: VERSION,
            stream: Stream::new("pdp-fixture", "inst-1"),
            seq,
            prev: prev.clone(),
            at: "2026-10-01T00:00:00Z".to_owned(),
            body: body(seq),
        };
        let appended = spool
            .append(&record.to_value().expect("the record renders"))
            .expect("the record appends");
        prev = appended.digest;
    }
}

fn verify(directory: &Path) {
    let spool = Spool::open(directory, Bounds::default()).expect("the fixture opens");
    assert_eq!(spool.seq(), 3, "three records are recovered");
    let records = spool.read_from(0, 10).expect("the records read");
    assert_eq!(records.len(), 3);
    let typed: Vec<Record> = records
        .iter()
        .map(|value| serde_json::from_value(value.clone()).expect("a typed decision record"))
        .collect();
    assert!(
        matches!(typed[0].body, Body::Marker(_)),
        "the stream opens with its marker"
    );
    for (record, (id, permitted)) in typed[1..].iter().zip([("d-2", true), ("d-3", false)]) {
        let Body::Decision(decision) = &record.body else {
            panic!("record {} is not a decision", record.seq);
        };
        assert_eq!(decision.id, id);
        assert_eq!(decision.decision, permitted);
    }
    assert_eq!(
        spool.head(),
        digest_of(&records[2]).expect("the last record digests"),
        "the head is the digest of the last record"
    );
    assert_eq!(spool.acked(), 0);
    assert!(directory.join("STATE").exists());
    assert!(directory.join("RESERVE").exists());
}

#[test]
fn test_the_v1_decision_spool_fixture_is_read_by_the_current_code() {
    let work = scratch();
    if std::env::var_os("PERMGUARD_CAPTURE_LEGACY_FIXTURES").is_some() {
        build(&work);
        let _ = fs::remove_dir_all(FIXTURE);
        copy_dir(&work, Path::new(FIXTURE));
        // The writer's pid, for a human reading a live volume; the claim itself is the advisory
        // lock, which a copied file does not carry. Emptied so the fixture holds no machine data.
        fs::write(Path::new(FIXTURE).join("LOCK"), b"").expect("the lock file is emptied");
    } else {
        copy_dir(Path::new(FIXTURE), &work);
    }
    verify(&work);
}
