// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! F-04 (WP-5.3): two producer Hosts interleave their batches on one ledger for an hour, on a
//! manual clock, shipping to one consumer Host: each sometimes resends a batch, sometimes sends
//! one ahead of its turn. After every round, every record acknowledged is readable in the tenant
//! view, and no read shows a record a later read lacks.

#![allow(clippy::expect_used, clippy::unwrap_used)]

mod support;

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use permguard_host::keys::ring::{DATA_ATTEST, Policy};
use permguard_host::membership::record::{RingPin, Role};
use permguard_host::time::{ManualClock, ManualMonotonic, TimeGuard};
use permguard_stream::engine::ingest::{Answer, Outcome, Ship, Shipping};
use permguard_stream::engine::{Consumer, Fence, Sealing, Streams};

use support::{Host, Text, descriptor, ledger, scratch};

fn pin_of(host: &Host) -> RingPin {
    let statement = host.attest.statement().expect("a statement");
    RingPin {
        owner: Role::Member,
        ring: DATA_ATTEST.to_owned(),
        epoch: statement.epoch,
        key_set_digest: statement.key_set_digest,
        binding: statement.binding.expect("a binding"),
        retiring: false,
    }
}

fn ship(host: &Host, consumer: &Consumer<Text>, membership: [u8; 16], batch: &[u8]) -> Answer {
    let body = Ship {
        batch: batch.to_vec(),
        statement: permguard_host::membership::statement_of(&host.attest)
            .expect("a statement")
            .encode()
            .expect("encodes"),
    }
    .encode()
    .expect("encodes");
    let pins = vec![pin_of(host)];
    let pinned = move |_: &str, _: u64| pins.clone();
    let resource = ledger(1).to_string();
    let (answer, forked) = consumer
        .ingest(
            &Shipping {
                membership_id: membership,
                epoch: 1,
                member: host.identity.host_id(),
                resource: &resource,
                pins: &pinned,
            },
            &body,
        )
        .expect("ingested");
    assert_eq!(forked, None);
    answer
}

#[test]
fn two_producers_interleave_for_an_hour_and_no_record_disappears() {
    let wall = Arc::new(ManualClock::at(
        i64::try_from(permguard_host::authz::store::now()).expect("in range"),
    ));
    let mono = Arc::new(ManualMonotonic::default());
    let time = Arc::new(TimeGuard::new(
        wall.clone(),
        mono.clone(),
        Duration::from_secs(30),
    ));
    let policy = Policy {
        publish_ahead: Duration::from_secs(600),
        rotate_every: Duration::from_secs(7200),
        retain: Duration::from_secs(86_400),
    };
    let root = scratch("ingest-f04");
    let producers: Vec<(Host, [u8; 16])> = (1..=2u8)
        .map(|n| {
            (
                Host::open(
                    &root.join(format!("producer-{n}")),
                    Arc::clone(&time),
                    policy,
                ),
                [n; 16],
            )
        })
        .collect();
    let coordinator = Host::open(&root.join("coordinator"), Arc::clone(&time), policy);
    let consumer = Streams::open(
        &coordinator.volume,
        &coordinator.identity,
        Arc::clone(&coordinator.operations),
        Arc::clone(&coordinator.time),
    )
    .expect("the engine opens")
    .register_consumer(descriptor(), Text)
    .expect("registered");
    let handles: Vec<_> = producers
        .iter()
        .map(|(host, membership)| {
            let producer = host.sealer();
            let run = producer
                .open_run(
                    &ledger(1),
                    Some(Fence {
                        membership_id: *membership,
                        task_id: "decisions".to_owned(),
                        epoch: 1,
                    }),
                )
                .expect("opened")
                .run_id;
            (producer, run)
        })
        .collect();
    // Each producer's batches not yet acknowledged, oldest first.
    let mut queued: Vec<Vec<Vec<u8>>> = vec![Vec::new(), Vec::new()];
    let mut appended: Vec<Vec<String>> = vec![Vec::new(), Vec::new()];
    let mut seen: Vec<Vec<String>> = vec![Vec::new(), Vec::new()];
    // An hour in steps of thirty seconds.
    for step in 0..120u64 {
        for (at, ((producer, _), (host, membership))) in handles.iter().zip(&producers).enumerate()
        {
            for n in 0..(1 + (step + at as u64) % 3) {
                let text = format!("p{at}-{step}-{n}");
                producer.append(&ledger(1), &text).expect("appended");
                appended[at].push(text);
            }
            while let Sealing::Sealed { bytes, .. } = producer.seal(&ledger(1), 2).expect("sealed")
            {
                queued[at].push(bytes);
            }
            // Every fifth step, the newest batch first: `out_of_order`, then the turn's order.
            if step % 5 == 4 && queued[at].len() > 1 {
                let ahead = queued[at].last().expect("a batch").clone();
                let answer = ship(host, &consumer, *membership, &ahead);
                assert_eq!(answer.outcome, Outcome::OutOfOrder);
            }
            let mut acknowledged = 0;
            for batch in &queued[at] {
                let answer = ship(host, &consumer, *membership, batch);
                assert_eq!(answer.outcome, Outcome::Ok, "step {step}");
                acknowledged = answer.acked;
            }
            // Every seventh step, the last batch resent: an exact replay.
            if step % 7 == 6
                && let Some(batch) = queued[at].last()
            {
                assert_eq!(
                    ship(host, &consumer, *membership, batch),
                    Answer::of(Outcome::Ok, acknowledged)
                );
            }
            queued[at].clear();
        }
        // The tenant view: every producer's records, every one acknowledged, none lost since.
        let view: BTreeMap<usize, Vec<String>> = handles
            .iter()
            .zip(&producers)
            .enumerate()
            .map(|(at, ((_, run), (host, _)))| {
                let records = consumer
                    .read(&ledger(1), host.identity.host_id(), *run, 1, usize::MAX)
                    .expect("read")
                    .records
                    .into_iter()
                    .map(|(_, text)| text)
                    .collect::<Vec<_>>();
                (at, records)
            })
            .collect();
        for (at, records) in view {
            assert_eq!(
                records, appended[at],
                "step {step}: the tenant view of producer {at}"
            );
            assert!(
                records.starts_with(&seen[at]),
                "step {step}: a record read before is gone"
            );
            seen[at] = records;
        }
        wall.jump(30);
        mono.advance(Duration::from_secs(30));
        for (host, _) in &producers {
            host.maintain();
        }
    }
    assert!(seen.iter().all(|records| records.len() > 200));
}
