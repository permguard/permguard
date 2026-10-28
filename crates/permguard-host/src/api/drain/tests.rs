// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The drain receipt (TD-2): issued only for a complete drain, verified only under its Host's
//! bundle and pin, and only as a drain receipt.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::sync::Arc;

use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;

use super::*;
use crate::api::streams::{
    AnchorView, Frontier, GapEntry, ProducerRun, RecordPage, ResourceState, RunSigners,
    StreamReads, StreamView, SubscriptionView,
};
use crate::api::testing::{reopen_with, scratch};
use crate::operations::drain;

/// A stream engine holding one shipped stream of `ledger`, its runs as given.
struct Shipped(Vec<ProducerRun>);

impl StreamReads for Shipped {
    fn list(&self) -> Result<Vec<StreamView>, String> {
        Ok(vec![
            StreamView {
                plane: "data".to_owned(),
                stream_type: "decisions".to_owned(),
                version: 1,
                role: "producer".to_owned(),
                retention: "evidence".to_owned(),
                ring: "data.attest".to_owned(),
                task: Some("decisions.ship".to_owned()),
                resources: vec![ResourceState {
                    resource: LEDGER.to_owned(),
                    state: "open".to_owned(),
                }],
            },
            // A stream nobody ships is not the drain's.
            StreamView {
                plane: "data".to_owned(),
                stream_type: "events".to_owned(),
                version: 1,
                role: "producer".to_owned(),
                retention: "history".to_owned(),
                ring: "data.attest".to_owned(),
                task: None,
                resources: vec![ResourceState {
                    resource: LEDGER.to_owned(),
                    state: "open".to_owned(),
                }],
            },
        ])
    }
    fn frontier(
        &self,
        plane: &str,
        kind: &str,
        resource: &str,
    ) -> Result<Option<Frontier>, String> {
        assert_eq!((plane, resource), ("data", LEDGER));
        Ok(Some(Frontier {
            resource: resource.to_owned(),
            producer: match kind {
                "decisions" => self.0.clone(),
                // The events stream, which no task ships, holds an empty run.
                _ => vec![run(RUN_C, 0, None)],
            },
            consumer: Vec::new(),
        }))
    }
    fn records(
        &self,
        _: &str,
        _: &str,
        _: &str,
        _: Option<(&[u8; 16], &[u8; 16])>,
        _: u64,
        _: usize,
    ) -> Result<Option<RecordPage>, String> {
        unreachable!()
    }
    fn signers(&self, _: &str, _: &str, _: &str) -> Result<Option<Vec<RunSigners>>, String> {
        unreachable!()
    }
    fn subscriptions(
        &self,
        _: &str,
        _: &str,
        _: &str,
    ) -> Result<Option<Vec<SubscriptionView>>, String> {
        unreachable!()
    }
    fn gaps(&self, _: &str, _: &str, _: &str) -> Result<Option<Vec<GapEntry>>, String> {
        unreachable!()
    }
    fn anchors(&self, _: &str, _: &str, _: &str) -> Result<Option<Vec<AnchorView>>, String> {
        unreachable!()
    }
}

const LEDGER: &str = "plane/data/zone/acme/ledger/main";
const RUN_A: &str = "0a0b0a0b0a0b0a0b0a0b0a0b0a0b0a0b";
const RUN_B: &str = "0c0d0c0d0c0d0c0d0c0d0c0d0c0d0c0d";
const RUN_C: &str = "0e0f0e0f0e0f0e0f0e0f0e0f0e0f0e0f";
const VOLUME: [u8; 16] = [7; 16];

fn run(run: &str, last_seq: u64, acknowledged: Option<u64>) -> ProducerRun {
    ProducerRun {
        run: run.to_owned(),
        ended: false,
        last_seq,
        sealed: last_seq,
        acknowledged,
        low_watermark: 1,
    }
}

fn host(tag: &str, runs: Vec<ProducerRun>) -> HostApi {
    let root = scratch(tag);
    let (api, _, volume) = reopen_with(
        &root,
        vec![HOST_OPERATIONS],
        Arc::new(crate::api::testing::Recording::default()),
    );
    std::mem::forget(volume);
    api.with_streams(Arc::new(Shipped(runs)))
        .with_volume(VOLUME, 3)
}

fn bytes(export: &DrainReceiptExport) -> (Vec<u8>, Vec<u8>, Vec<Vec<u8>>) {
    (
        B64.decode(&export.receipt).unwrap(),
        B64.decode(&export.bundle.manifest).unwrap(),
        export
            .bundle
            .items
            .iter()
            .map(|item| B64.decode(item).unwrap())
            .collect(),
    )
}

fn pin(api: &HostApi) -> String {
    api.keys.identity().unwrap().first_fingerprint().to_owned()
}

#[test]
fn a_complete_drain_issues_a_receipt_that_verifies_under_its_pin() {
    let api = host(
        "drain-receipt",
        vec![
            run(RUN_A, 12, Some(12)),
            // A run without records owes nothing.
            run(RUN_B, 0, None),
        ],
    );
    let export = api.drain_receipt_at(1_800_000_000).expect("issued");
    let (receipt, manifest, items) = bytes(&export);

    let verified = drain::verify(&receipt, &manifest, &items, &pin(&api)).expect("verifies");
    assert_eq!(verified.host_id, api.keys.identity().unwrap().host_id());
    assert_eq!(verified.volume_id, VOLUME);
    assert_eq!(verified.generation, 3);
    assert_eq!(verified.drained_at, 1_800_000_000);
    assert_eq!(
        verified.streams,
        vec![drain::DrainedStream {
            plane: "data".to_owned(),
            stream_type: "decisions".to_owned(),
            resource: LEDGER.to_owned(),
            run: RUN_A.to_owned(),
            last_seq: 12,
            acknowledged: 12,
        }]
    );
}

#[test]
fn a_stream_behind_its_subscriptions_issues_no_receipt() {
    let api = host("drain-behind", vec![run(RUN_A, 12, Some(11))]);
    let refused = api
        .drain_receipt_at(1_800_000_000)
        .expect_err("not drained");
    assert!(
        refused.contains("acknowledged through 11 of 12"),
        "{refused}"
    );
}

#[test]
fn records_no_required_subscription_acknowledges_issue_no_receipt() {
    // Recorded before any membership fenced a run, or under a subscription that is not required.
    let api = host(
        "drain-unsubscribed",
        vec![run(RUN_A, 12, Some(12)), run(RUN_B, 4, None)],
    );
    let refused = api
        .drain_receipt_at(1_800_000_000)
        .expect_err("the volume is their only copy");
    assert!(
        refused.contains("no required subscription acknowledges"),
        "{refused}"
    );
    // A run whose prefix is gone holds nothing.
    let mut pruned = run(RUN_B, 4, None);
    pruned.low_watermark = 5;
    let api = host("drain-pruned", vec![run(RUN_A, 12, Some(12)), pruned]);
    api.drain_receipt_at(1_800_000_000)
        .expect("nothing is owed");
}

#[test]
fn a_receipt_verifies_only_under_its_own_hosts_pin_and_bytes() {
    let api = host("drain-pin", vec![run(RUN_A, 2, Some(2))]);
    let (receipt, manifest, items) = bytes(&api.drain_receipt_at(1).expect("issued"));

    let refused = drain::verify(&receipt, &manifest, &items, "sha256:another").expect_err("pin");
    assert!(refused.contains("bundle"), "{refused}");

    // Another Host's bundle and pin: its keys do not hold the receipt's kid.
    let other = host("drain-other", Vec::new());
    let (_, other_manifest, other_items) = bytes(&other.drain_receipt_at(1).expect("issued"));
    assert!(drain::verify(&receipt, &other_manifest, &other_items, &pin(&other)).is_err());

    // One byte of the signed envelope changed.
    let mut forged = receipt.clone();
    let last = forged.len() - 1;
    forged[last] ^= 1;
    assert!(drain::verify(&forged, &manifest, &items, &pin(&api)).is_err());
}

#[test]
fn another_signed_statement_is_not_a_drain_receipt() {
    use crate::operations::backup::{SnapshotManifest, sign as sign_manifest};

    let api = host("drain-type", Vec::new());
    let (_, manifest, items) = bytes(&api.drain_receipt_at(1).expect("issued"));
    // A snapshot manifest, signed by the same `host.operations` key, presented as a receipt.
    let snapshot = SnapshotManifest {
        operation_id: [1; 16],
        volume_id: VOLUME,
        host_id: api.keys.identity().unwrap().host_id(),
        revisions: Default::default(),
        roots: Vec::new(),
        at: 1,
        inventory_digest: [0; 32],
        recovery_key_id: None,
        encryption_profile: None,
    };
    let ring = api.keys.ring(HOST_OPERATIONS).unwrap();
    let envelope = sign_manifest(ring, &snapshot).expect("signed");
    let refused = drain::verify(&envelope, &manifest, &items, &pin(&api)).expect_err("type");
    assert!(!refused.is_empty());
}

#[test]
fn the_receipt_payload_is_closed() {
    let receipt = drain::DrainReceipt {
        host_id: [1; 16],
        volume_id: [2; 16],
        generation: 3,
        drained_at: 4,
        streams: vec![drain::DrainedStream {
            plane: "data".to_owned(),
            stream_type: "decisions".to_owned(),
            resource: LEDGER.to_owned(),
            run: "ff".repeat(16),
            last_seq: 5,
            acknowledged: 5,
        }],
    };
    let encoded = receipt.encode().expect("encodes");
    assert_eq!(
        drain::DrainReceipt::decode(&encoded).expect("decodes"),
        receipt
    );

    // A run that is not lowercase hex is neither written nor read.
    let mut bad = receipt.clone();
    bad.streams[0].run = "FF".repeat(16);
    assert!(bad.encode().is_err());
    bad.streams[0].run = "ff".to_owned();
    assert!(bad.encode().is_err());
    // An unknown label is refused.
    use permguard_objects::cbor::{self, Value};
    let Value::Map(mut pairs) = cbor::decode_canonical(&encoded).unwrap() else {
        panic!("a map")
    };
    pairs.push((Value::Int(7), Value::Int(0)));
    assert!(drain::DrainReceipt::decode(&cbor::encode(&Value::Map(pairs)).unwrap()).is_err());
    // Another version is refused.
    let Value::Map(mut pairs) = cbor::decode_canonical(&encoded).unwrap() else {
        panic!("a map")
    };
    pairs[0].1 = Value::Int(2);
    assert!(drain::DrainReceipt::decode(&cbor::encode(&Value::Map(pairs)).unwrap()).is_err());
}

/// Writes the drain receipts the command line's reclamation tests verify, to the file
/// `PERMGUARD_WRITE_DRAIN_RECEIPTS` names: a Host that shipped two runs, and another Host. Run once,
/// by hand, when the receipt changes; the file is checked in, so a change that breaks verifying it
/// breaks those tests.
#[test]
#[ignore = "writes the reclamation fixtures"]
fn write_the_reclamation_fixtures() {
    let Some(path) = std::env::var_os("PERMGUARD_WRITE_DRAIN_RECEIPTS") else {
        return;
    };
    let fixture = |api: &HostApi| {
        let export = api.drain_receipt_at(1_800_000_000).expect("issued");
        let identity = api.keys.identity().unwrap();
        serde_json::json!({
            "export": export,
            "pin": identity.first_fingerprint(),
            "host_id": identity.host_id_text(),
            "host_id_hex": identity.host_id().iter().map(|byte| format!("{byte:02x}")).collect::<String>(),
            "generation": 3,
        })
    };
    let shipped = host(
        "drain-fixture-shipped",
        vec![run(RUN_A, 12, Some(12)), run(RUN_B, 7, Some(7))],
    );
    let other = host("drain-fixture-other", Vec::new());
    let file = serde_json::json!({
        "comment": "Written by permguard-host api::drain::tests::write_the_reclamation_fixtures; verified by permguard-cli tests/reclaim.rs.",
        "shipped": fixture(&shipped),
        "other": fixture(&other),
    });
    std::fs::write(path, serde_json::to_string_pretty(&file).unwrap() + "\n").expect("written");
}

#[test]
fn a_receipt_naming_another_host_does_not_verify_under_its_signers_bundle() {
    let api = host("drain-other-host", Vec::new());
    let (_, manifest, items) = bytes(&api.drain_receipt_at(1).expect("issued"));
    // Signed by this Host's `host.operations` key, naming another Host.
    let forged = drain::DrainReceipt {
        host_id: [9; 16],
        volume_id: VOLUME,
        generation: 3,
        drained_at: 1,
        streams: Vec::new(),
    };
    let ring = api.keys.ring(HOST_OPERATIONS).unwrap();
    let envelope = drain::sign(ring, &forged).expect("signed");
    let refused =
        drain::verify(&envelope, &manifest, &items, &pin(&api)).expect_err("another Host");
    assert!(refused.contains("another Host"), "{refused}");
}

#[test]
fn a_receipt_is_bounded_in_bytes() {
    let long = format!("plane/data/zone/{}/ledger/main", "z".repeat(300));
    let receipt = drain::DrainReceipt {
        host_id: [1; 16],
        volume_id: [2; 16],
        generation: 3,
        drained_at: 4,
        streams: (0..drain::MAX_STREAMS)
            .map(|_| drain::DrainedStream {
                plane: "data".to_owned(),
                stream_type: "decisions".to_owned(),
                resource: long.clone(),
                run: "ab".repeat(16),
                last_seq: 1,
                acknowledged: 1,
            })
            .collect(),
    };
    let refused = receipt.encode().expect_err("past the bytes");
    assert!(refused.contains("at most"), "{refused}");
}
