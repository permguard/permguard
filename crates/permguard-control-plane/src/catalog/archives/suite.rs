// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The conformance suite of [`ArchiveStore`]: what every backend of the contract does the same
//! way (`1-architecture/8` Store contracts).
//!
//! [`run`] takes how a backend makes one empty store and runs every case on a store of its own.
//! A case panics with what it expected, as a test does. A backend proves what only it can, that
//! an archive is kept verbatim where it keeps it and what it does of one a crash cut short, in
//! its own tests.
//!
//! | Case                                 | Rule of the contract                                        |
//! | ------------------------------------ | ----------------------------------------------------------- |
//! | `an_empty_store`                     | a zone keeps nothing, and no request kept anything          |
//! | `an_archive_is_kept_and_found`       | listed by its record, found by the request that kept it     |
//! | `a_request_keeps_one_archive`        | a second archive under one request id is answered the first |
//! | `a_zone_keeps_one_archive_a_name`    | a second archive of one name is refused, nothing written    |
//! | `zones_keep_their_own`               | a name and a request id are a zone's, not the store's       |
//! | `requests_together_keep_one`         | of the keeps of one request id at once, one is kept         |
//! | `names_together_keep_one`            | of the keeps of one name at once, one is kept               |

#![allow(clippy::expect_used, clippy::panic)]

use std::sync::{Arc, Barrier};

use super::{ArchiveStore, Keeping, Requested};
use crate::catalog::imports::{ArchiveRecord, ArchivedLedger};

const ZONE: &str = "01a00000-0000-7000-8000-00000000000a";
const OTHER: &str = "01a00000-0000-7000-8000-00000000000b";

/// How many callers a concurrency case releases at once, and how many times it does.
const TOGETHER: usize = 8;
const ROUNDS: usize = 4;

/// Runs every case, each on a store `make` made empty for it.
pub fn run(make: &dyn Fn() -> Arc<dyn ArchiveStore>) {
    an_empty_store(make().as_ref());
    an_archive_is_kept_and_found(make().as_ref());
    a_request_keeps_one_archive(make().as_ref());
    a_zone_keeps_one_archive_a_name(make().as_ref());
    zones_keep_their_own(make().as_ref());
    requests_together_keep_one(make().as_ref());
    names_together_keep_one(make().as_ref());
}

/// The record of the archive `n`, named `name`.
fn record(n: usize, name: &str) -> ArchiveRecord {
    ArchiveRecord {
        id: format!("01c00000-0000-7000-8000-{n:012x}"),
        name: name.to_owned(),
        imported_at: 1_800_000_000,
        manifest_digest: format!("sha256:{}", "ab".repeat(32)),
        source_host_id: "11".repeat(16),
        source_zone_id: "01d00000-0000-7000-8000-00000000000a".to_owned(),
        source_zone_name: "delivery".to_owned(),
        ledgers: vec![ArchivedLedger {
            id: "01d00000-0000-7000-8000-00000000000b".to_owned(),
            name: "policies".to_owned(),
            refs: 1,
            objects: 4,
            statements: 1,
        }],
    }
}

/// What the request `request_id` asks when it keeps `record`.
fn asked(request_id: &str, record: &ArchiveRecord) -> Requested {
    Requested {
        request_id: request_id.to_owned(),
        name: record.name.clone(),
        manifest_digest: record.manifest_digest.clone(),
    }
}

/// Keeps the archive `n` named `name` under `request_id` in `zone`.
fn keep(store: &dyn ArchiveStore, zone: &str, n: usize, name: &str, request_id: &str) -> Keeping {
    let record = record(n, name);
    store
        .keep(
            zone,
            format!("archive {n}").as_bytes(),
            &asked(request_id, &record),
            &record,
        )
        .expect("the store answers")
}

fn an_empty_store(store: &dyn ArchiveStore) {
    assert!(store.archived(ZONE).expect("listed").is_empty());
    assert_eq!(store.kept_by(ZONE, "import-1").expect("read"), None);
}

fn an_archive_is_kept_and_found(store: &dyn ArchiveStore) {
    assert_eq!(keep(store, ZONE, 1, "backup", "import-1"), Keeping::Kept);
    assert_eq!(keep(store, ZONE, 2, "audit", "import-2"), Keeping::Kept);
    let mut listed = store.archived(ZONE).expect("listed");
    listed.sort_by(|a, b| a.id.cmp(&b.id));
    assert_eq!(listed, [record(1, "backup"), record(2, "audit")]);
    assert_eq!(
        store.kept_by(ZONE, "import-2").expect("read"),
        Some((record(2, "audit"), asked("import-2", &record(2, "audit"))))
    );
    assert_eq!(store.kept_by(ZONE, "import-3").expect("read"), None);
}

fn a_request_keeps_one_archive(store: &dyn ArchiveStore) {
    assert_eq!(keep(store, ZONE, 1, "backup", "import-1"), Keeping::Kept);
    let first = (record(1, "backup"), asked("import-1", &record(1, "backup")));
    // The same request again, and the same id asking for another archive: both are answered
    // what the first kept, and it is the caller's to tell a retry from a reuse.
    for (n, name) in [(2, "backup"), (3, "other")] {
        assert_eq!(
            keep(store, ZONE, n, name, "import-1"),
            Keeping::Requested(Box::new(first.0.clone()), first.1.clone())
        );
    }
    assert_eq!(store.archived(ZONE).expect("listed"), [record(1, "backup")]);
}

fn a_zone_keeps_one_archive_a_name(store: &dyn ArchiveStore) {
    assert_eq!(keep(store, ZONE, 1, "backup", "import-1"), Keeping::Kept);
    assert_eq!(keep(store, ZONE, 2, "backup", "import-2"), Keeping::Named);
    assert_eq!(store.archived(ZONE).expect("listed"), [record(1, "backup")]);
    assert_eq!(
        store.kept_by(ZONE, "import-2").expect("read"),
        None,
        "a refused keep leaves nothing a retry would find"
    );
    assert_eq!(keep(store, ZONE, 2, "backup-2", "import-2"), Keeping::Kept);
}

fn zones_keep_their_own(store: &dyn ArchiveStore) {
    assert_eq!(keep(store, ZONE, 1, "backup", "import-1"), Keeping::Kept);
    assert_eq!(keep(store, OTHER, 2, "backup", "import-1"), Keeping::Kept);
    assert_eq!(store.archived(ZONE).expect("listed"), [record(1, "backup")]);
    assert_eq!(
        store.archived(OTHER).expect("listed"),
        [record(2, "backup")]
    );
    assert_eq!(
        store
            .kept_by(OTHER, "import-1")
            .expect("read")
            .map(|(record, _)| record.id),
        Some(record(2, "backup").id)
    );
}

/// Releases `TOGETHER` callers at once on `call` and answers what each was answered.
fn together(call: &(dyn Fn(usize) -> Keeping + Sync)) -> Vec<Keeping> {
    let barrier = Barrier::new(TOGETHER);
    std::thread::scope(|scope| {
        let callers: Vec<_> = (0..TOGETHER)
            .map(|caller| {
                let barrier = &barrier;
                scope.spawn(move || {
                    barrier.wait();
                    call(caller)
                })
            })
            .collect();
        callers
            .into_iter()
            .map(|caller| caller.join().expect("a caller finished"))
            .collect()
    })
}

fn requests_together_keep_one(store: &dyn ArchiveStore) {
    for round in 0..ROUNDS {
        let request_id = format!("import-{round}");
        let answers = together(&|caller| {
            keep(
                store,
                ZONE,
                round * TOGETHER + caller,
                &format!("backup-{round}-{caller}"),
                &request_id,
            )
        });
        let kept = store
            .kept_by(ZONE, &request_id)
            .expect("read")
            .expect("one was kept");
        let mut won = 0;
        for answer in &answers {
            match answer {
                Keeping::Kept => won += 1,
                Keeping::Requested(record, asked) => {
                    assert_eq!((record.as_ref(), asked), (&kept.0, &kept.1));
                }
                Keeping::Named => panic!("no name was taken"),
            }
        }
        assert_eq!(won, 1, "one request id, one archive: {answers:?}");
        assert_eq!(store.archived(ZONE).expect("listed").len(), round + 1);
    }
}

fn names_together_keep_one(store: &dyn ArchiveStore) {
    for round in 0..ROUNDS {
        let name = format!("backup-{round}");
        let answers = together(&|caller| {
            keep(
                store,
                ZONE,
                round * TOGETHER + caller,
                &name,
                &format!("import-{round}-{caller}"),
            )
        });
        let won = answers
            .iter()
            .filter(|answer| **answer == Keeping::Kept)
            .count();
        assert_eq!(won, 1, "one name, one archive: {answers:?}");
        assert!(
            answers
                .iter()
                .all(|answer| matches!(answer, Keeping::Kept | Keeping::Named)),
            "{answers:?}"
        );
        assert_eq!(store.archived(ZONE).expect("listed").len(), round + 1);
    }
}
