// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::expect_used, clippy::unwrap_used)]

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use permguard_stream::engine::batch::digest_string;
use serde_json::json;

use super::testing::{Key, sealed};
use super::*;

/// A Host entry for records 1-2 of run `[7; 16]` of the Host `[1; 16]`, signed under `key`.
fn entry(key: &Key, typ: &str) -> (Value, String) {
    let records = [b"{\"seq\":1}".to_vec(), b"{\"seq\":2}".to_vec()];
    let leaves: Vec<String> = records
        .iter()
        .map(|record| digest_string(permguard_core::domains::digest::EVENT_RECORD, record))
        .collect();
    let root = permguard_stream::merkle::root(&leaves).expect("a root");
    (
        sealed(
            key,
            typ,
            permguard_core::domains::digest::EVENT_RECORD,
            &"01".repeat(16),
            &"07".repeat(16),
            1,
            &records,
        ),
        root,
    )
}

#[test]
fn a_host_entry_verifies_under_its_key_and_names_its_run() {
    let key = Key::new("k1");
    let typ = permguard_core::domains::protected::EVENT_BATCH;
    let (value, root) = entry(&key, typ);
    let batch = host_batch(&value, Some(&[key.jwk()]), typ)
        .expect("a Host entry")
        .expect("it holds");
    assert_eq!(batch.producer, "01".repeat(16));
    assert_eq!(batch.run, "07".repeat(16));
    assert_eq!(batch.merkle_root, root);
    assert!(batch.covers(&"01".repeat(16), &"07".repeat(16), 2));
    assert!(!batch.covers(&"01".repeat(16), &"07".repeat(16), 3));
    assert!(!batch.covers(&"02".repeat(16), &"07".repeat(16), 1));
    assert!(!batch.covers(&"01".repeat(16), &"08".repeat(16), 1));
    // Another key, or the other stream type's batch, does not hold.
    assert_eq!(
        host_batch(&value, Some(&[Key::new("k1").jwk()]), typ),
        Some(Err(()))
    );
    assert_eq!(
        host_batch(
            &value,
            Some(&[key.jwk()]),
            permguard_core::domains::protected::DECISION_BATCH
        ),
        Some(Err(()))
    );
    // Without keys it is read, never attributed.
    assert!(matches!(host_batch(&value, None, typ), Some(Ok(_))));
}

#[test]
fn a_legacy_entry_is_not_a_host_entry_and_a_broken_one_does_not_hold() {
    let typ = permguard_core::domains::protected::EVENT_BATCH;
    assert_eq!(
        host_batch(
            &json!({"format": "legacy-jws-v1", "protected": "e30", "payload": "e30", "signature": "c2ln"}),
            None,
            typ
        ),
        None
    );
    assert_eq!(
        host_batch(&json!({"protected": "e30"}), None, typ),
        None,
        "an entry naming no format is the legacy one"
    );
    assert_eq!(
        host_batch(
            &json!({"format": HOST_FORMAT, "signature": {"protected": "e30"}}),
            None,
            typ
        ),
        Some(Err(()))
    );
    let key = Key::new("k1");
    let (mut value, _) = entry(&key, typ);
    value["signature"]["signature"] = json!(B64.encode([0u8; 64]));
    assert_eq!(host_batch(&value, Some(&[key.jwk()]), typ), Some(Err(())));
}

#[test]
fn a_signed_envelope_whose_range_and_count_disagree_does_not_hold() {
    use permguard_stream::engine::batch::{Envelope, KeyView, SealedBatch};

    let key = Key::new("k1");
    let typ = permguard_core::domains::protected::EVENT_BATCH;
    let run = "07".repeat(16);
    let signed = |first_seq: u64, last_seq: u64, count: u64| {
        let envelope = Envelope {
            descriptor_version: 1,
            stream_key: KeyView {
                plane: "data".to_owned(),
                stream_type: "events".to_owned(),
                resource: "plane/data/zone/z/ledger/l".to_owned(),
                producer_host_id: "01".repeat(16),
            },
            run: run.clone(),
            membership_id: None,
            epoch: None,
            first_seq,
            last_seq,
            count,
            previous_head: "sha256:00".to_owned(),
            head: "sha256:01".to_owned(),
            merkle_root: "sha256:02".to_owned(),
            batch_id: format!("{run}-{first_seq}"),
            created_at: "2026-10-19T10:00:00Z".to_owned(),
            key_set_epoch: 1,
        };
        let sealed = SealedBatch::seal(&key, &key.jwk(), typ, &envelope, &[]).expect("sealed");
        json!({"format": HOST_FORMAT, "signature": sealed.signature})
    };
    // Signed by the right key, and still not a batch: the range and the count are one claim.
    assert!(matches!(
        host_batch(&signed(1, 2, 2), Some(&[key.jwk()]), typ),
        Some(Ok(_))
    ));
    for (first, last, count) in [(1, 2, 3), (1, 2, 1), (0, 1, 2), (3, 2, 0)] {
        assert_eq!(
            host_batch(&signed(first, last, count), Some(&[key.jwk()]), typ),
            Some(Err(())),
            "{first}..={last} counted {count}"
        );
    }
}
