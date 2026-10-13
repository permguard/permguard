// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! F-01 (WP-5.2): the `data.attest` ring rotating every two minutes while a fenced and an
//! unfenced stream append and seal, on a manual clock. Every batch verifies under the span that
//! names its key, every chain runs from genesis without a gap or a fork, every record appended is
//! sealed exactly once, and a fenced stream's new key seals only from the sequence its journaled
//! cutover names.

#![allow(clippy::expect_used, clippy::unwrap_used)]

mod support;

use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::Duration;

use permguard_host::composition::StreamCutovers as _;
use permguard_host::keys::ring::{DATA_ATTEST, Policy};
use permguard_host::time::{ManualClock, ManualMonotonic, TimeGuard};
use permguard_stream::engine::{Fence, Sealing};

use support::{Host, every_batch, ledger, scratch};

#[test]
fn rotation_every_two_minutes_while_sealing_leaves_every_batch_verifiable() {
    let wall = Arc::new(ManualClock::at(
        i64::try_from(permguard_host::authz::store::now()).expect("in range"),
    ));
    let mono = Arc::new(ManualMonotonic::default());
    let time = Arc::new(TimeGuard::new(
        wall.clone(),
        mono.clone(),
        Duration::from_secs(30),
    ));
    let host = Host::open(
        &scratch("rotation"),
        time,
        Policy {
            publish_ahead: Duration::from_secs(60),
            rotate_every: Duration::from_secs(120),
            retain: Duration::from_secs(3600),
        },
    );
    let producer = host.sealer();
    let membership = [9; 16];
    producer
        .open_run(
            &ledger(1),
            Some(Fence {
                membership_id: membership,
                task_id: "decisions".to_owned(),
                epoch: 1,
            }),
        )
        .expect("opened");
    let mut appended = [Vec::new(), Vec::new()];
    let mut cutovers = Vec::new();
    // Forty minutes in steps of forty seconds: about twenty rotations.
    for step in 0..60 {
        for (at, resource) in [ledger(1), ledger(2)].iter().enumerate() {
            for n in 0..(1 + step % 4) {
                let text = format!("{step}-{n}");
                producer.append(resource, &text).expect("appended");
                appended[at].push(text.into_bytes());
            }
            loop {
                match producer.seal(resource, 3).expect("sealed") {
                    Sealing::Sealed { .. } => {}
                    Sealing::Nothing => break,
                    Sealing::AwaitingCutover { stream, from_seq } => {
                        // The coordinator journals what the member names, then the member is told.
                        use permguard_core::keys::Sign as _;
                        let kid = host.attest.active_key_id().expect("a key");
                        let due = producer
                            .due(&membership, DATA_ATTEST, kid.as_str())
                            .expect("due");
                        assert_eq!(due, vec![(stream, from_seq)]);
                        producer
                            .journaled(DATA_ATTEST, kid.as_str(), &due)
                            .expect("confirmed");
                        cutovers.push(due[0].1);
                    }
                }
            }
        }
        wall.jump(40);
        mono.advance(Duration::from_secs(40));
        host.maintain();
    }
    let mut kids = BTreeSet::new();
    for (at, resource) in [ledger(1), ledger(2)].iter().enumerate() {
        let spans = producer.spans(resource).expect("spans");
        let batches = every_batch(&host.producer_dir(resource), &spans);
        let sealed: Vec<Vec<u8>> = batches
            .iter()
            .flat_map(|batch| batch.records.clone())
            .collect();
        assert_eq!(sealed, appended[at], "every record sealed once, in order");
        kids.extend(batches.iter().map(|batch| batch.kid.clone()));
        // A span starts where a batch does, and its key signs that batch.
        for (run, spans) in &spans.runs {
            for span in spans {
                assert!(
                    batches.iter().any(|batch| batch.run == *run
                        && batch.envelope.first_seq == span.from_seq
                        && batch.kid == span.kid),
                    "a span starts at a batch it signs"
                );
            }
        }
        if at == 0 {
            // The fenced stream's spans after the first start where a cutover said.
            let starts: Vec<u64> = spans.runs[0]
                .1
                .iter()
                .skip(1)
                .map(|span| span.from_seq)
                .collect();
            assert_eq!(starts, cutovers);
        }
    }
    assert!(
        kids.len() >= 10,
        "{} keys signed: the ring rotated",
        kids.len()
    );
    assert!(cutovers.len() >= 9, "{} cutovers", cutovers.len());
}
