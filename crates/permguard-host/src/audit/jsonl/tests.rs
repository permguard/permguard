// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::expect_used)]

use std::path::{Path, PathBuf};

use super::*;

/// The WP-0.5 fixture: a day of three records, sealed and signed by the directory key manager.
const FIXTURE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../permguard-std/tests/fixtures/legacy/v1/audit"
);

fn scratch(tag: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!(
        "permguard-host-audit-legacy-{tag}-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&path);
    path
}

/// A copy of the fixture's day and seal in `into`.
fn copy_trail(into: &Path) {
    std::fs::create_dir_all(into).expect("created");
    for entry in std::fs::read_dir(Path::new(FIXTURE).join("trail")).expect("the fixture") {
        let entry = entry.expect("an entry");
        std::fs::copy(entry.path(), into.join(entry.file_name())).expect("copied");
    }
}

/// The fixture's sealing key as `keys export` names it once WP-3.1 migrated it.
fn fixture_keys(revoked: bool) -> Keys {
    let ring: serde_json::Value = serde_json::from_slice(
        &std::fs::read(Path::new(FIXTURE).join("keys/ring.json")).expect("the ring"),
    )
    .expect("json");
    let key = &ring["keys"][0];
    let kid = format!("host.operations:{}", key["kid"].as_str().expect("kid"));
    let mut document = serde_json::json!({
        "keys": [{
            "kid": kid,
            "kty": "OKP",
            "crv": "Ed25519",
            "x": key["public_key"],
            "alg": "EdDSA",
            "use": "sig",
        }],
    });
    if revoked {
        document["revoked"] = serde_json::json!([{ "kid": kid }]);
    }
    Keys::from_document(&document.to_string()).expect("the keys read")
}

fn day_file(dir: &Path) -> PathBuf {
    dir.join("audit-2026-10-02.jsonl")
}

fn seal_file(dir: &Path) -> PathBuf {
    dir.join("audit-2026-10-02.seal")
}

#[test]
fn the_fixture_verifies_with_its_seal_signed() {
    let dir = scratch("fixture");
    copy_trail(&dir);
    let verified = verify(&dir, Some(&fixture_keys(false))).expect("the fixture verifies");
    assert_eq!(
        (verified.records, verified.days, verified.first_seq),
        (3, 1, Some(1))
    );
    assert!(verified.warnings.is_empty(), "{:?}", verified.warnings);
    assert_eq!(verified.seals.len(), 1);
    assert!(
        matches!(
            &verified.seals[0].signature,
            SealSignature::Verified { revoked: false, .. }
        ),
        "{:?}",
        verified.seals[0]
    );
    // Without keys the chain and the seal's head are checked, the signature is not.
    let unchecked = verify(&dir, None).expect("verifies");
    assert_eq!(unchecked.seals[0].signature, SealSignature::NotChecked);
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn an_edited_record_breaks_the_chain() {
    let dir = scratch("edited");
    copy_trail(&dir);
    let text = std::fs::read_to_string(day_file(&dir)).expect("read");
    std::fs::write(
        day_file(&dir),
        text.replacen("fixture.zone.created", "fixture.zone.deleted", 1),
    )
    .expect("edited");
    let refused = verify(&dir, Some(&fixture_keys(false))).expect_err("altered");
    assert!(refused.contains("altered"), "{refused}");
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn a_truncated_tail_is_caught_by_its_seal() {
    let dir = scratch("truncated");
    copy_trail(&dir);
    let text = std::fs::read_to_string(day_file(&dir)).expect("read");
    let kept: Vec<&str> = text.lines().take(2).collect();
    std::fs::write(day_file(&dir), kept.join("\n") + "\n").expect("cut");
    let refused = verify(&dir, Some(&fixture_keys(false))).expect_err("cut");
    assert!(refused.contains("removed from the end"), "{refused}");
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn a_seal_signed_by_a_key_the_set_lacks_or_revoked_and_uncovered_fails() {
    let dir = scratch("other-key");
    copy_trail(&dir);
    let stranger = Keys::from_document(
        &serde_json::json!({ "keys": [{
            "kid": format!("host.operations:{}", "A".repeat(43)),
            "kty": "OKP",
            "crv": "Ed25519",
            "x": "PUAXw-hDiVqStwqnTRt-vJyYLM8uxJaMwM1V8Sr0Zgw",
            "alg": "EdDSA",
            "use": "sig",
        }]})
        .to_string(),
    )
    .expect("the keys read");
    let refused = verify(&dir, Some(&stranger)).expect_err("a key the set lacks");
    assert!(refused.contains("lacks"), "{refused}");
    let refused = verify(&dir, Some(&fixture_keys(true))).expect_err("revoked, nothing later");
    assert!(refused.contains("revoked since"), "{refused}");
    // A signature that does not verify: the seal's body changed, its head kept.
    let text = std::fs::read_to_string(seal_file(&dir)).expect("read");
    std::fs::write(
        seal_file(&dir),
        text.replacen("2026-10-02T20:47:02Z", "2026-10-02T20:47:03Z", 1),
    )
    .expect("edited");
    let refused = verify(&dir, Some(&fixture_keys(false))).expect_err("a wrong signature");
    assert!(refused.contains("does not verify"), "{refused}");
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn an_unsigned_seal_is_a_warning() {
    let dir = scratch("unsigned");
    copy_trail(&dir);
    let mut seal: Seal =
        serde_json::from_slice(&std::fs::read(seal_file(&dir)).expect("read")).expect("a seal");
    seal.kid = None;
    seal.algorithm = None;
    seal.signature = None;
    std::fs::write(
        seal_file(&dir),
        serde_json::to_vec_pretty(&seal).expect("json"),
    )
    .expect("written");
    let verified = verify(&dir, Some(&fixture_keys(false))).expect("verifies");
    assert_eq!(verified.seals[0].signature, SealSignature::Unsigned);
    assert!(
        verified
            .warnings
            .iter()
            .any(|warning| warning.contains("without a signature")),
        "{:?}",
        verified.warnings
    );
    let _ = std::fs::remove_dir_all(dir);
}

/// A day of records numbered `seqs`, chained, as the old sink wrote them.
fn synthetic(dir: &Path, seqs: &[u64]) {
    std::fs::create_dir_all(dir).expect("created");
    let mut previous = GENESIS.to_owned();
    let mut lines = String::new();
    for seq in seqs {
        let body = Body {
            seq: *seq,
            at: "2026-10-03T00:00:00Z".to_owned(),
            prev: previous.clone(),
            action: "server.start".to_owned(),
            subject: "default".to_owned(),
            subject_kind: "system".to_owned(),
            subject_sensitivity: "public".to_owned(),
            target: None,
            continuity_id: None,
            continuity_position: None,
            service: "permguard".to_owned(),
            version: "0.1.0".to_owned(),
        };
        let digest = Record::expected_digest(&body).expect("digest");
        lines.push_str(
            &serde_json::to_string(&Record {
                body,
                digest: digest.clone(),
            })
            .expect("json"),
        );
        lines.push('\n');
        previous = digest;
    }
    std::fs::write(dir.join("audit-2026-10-03.jsonl"), lines).expect("written");
}

#[test]
fn a_trail_trimmed_by_retention_verifies_with_a_warning() {
    let dir = scratch("trimmed");
    synthetic(&dir, &[5, 6, 7]);
    let verified = verify(&dir, None).expect("verifies from the first record kept");
    assert_eq!((verified.records, verified.first_seq), (3, Some(5)));
    assert!(
        verified
            .warnings
            .iter()
            .any(|warning| warning.contains("records 1..4 are absent")),
        "{:?}",
        verified.warnings
    );
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn a_gap_in_the_middle_fails() {
    let dir = scratch("gap");
    synthetic(&dir, &[1, 2, 4]);
    let refused = verify(&dir, None).expect_err("a record is missing");
    assert!(refused.contains("missing"), "{refused}");
    let _ = std::fs::remove_dir_all(dir);
}

fn claimed(tag: &str) -> (PathBuf, Volume) {
    let root = scratch(tag);
    let volume = Volume::claim(&root, AssuranceProfile::Development).expect("claimed");
    (root, volume)
}

#[test]
fn the_fixture_migrates_byte_for_byte_and_still_verifies() {
    let (root, volume) = claimed("migrate");
    let legacy = root.join("operations/audit");
    copy_trail(&legacy);
    assert!(needs_migration(&volume, Some(&legacy)).expect("read"));
    assert_eq!(
        lay_out(
            &volume,
            Some(&legacy),
            AssuranceProfile::Development,
            None,
            1_800_000_000
        )
        .expect("migrated"),
        Laid::Migrated
    );
    let migrated = root.join(target());
    for name in ["audit-2026-10-02.jsonl", "audit-2026-10-02.seal"] {
        assert_eq!(
            std::fs::read(migrated.join(name)).expect("carried"),
            std::fs::read(legacy.join(name)).expect("kept until finalize"),
            "{name} carried byte for byte"
        );
    }
    let verified = verify(&migrated, Some(&fixture_keys(false))).expect("still verifies");
    assert_eq!(verified.records, 3);
    assert!(!needs_migration(&volume, Some(&legacy)).expect("read"));
    assert_eq!(
        lay_out(
            &volume,
            Some(&legacy),
            AssuranceProfile::Development,
            None,
            1_800_000_000
        )
        .expect("laid out"),
        Laid::Current
    );
    drop(volume);
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn a_foreign_file_stops_the_migration() {
    let (root, volume) = claimed("foreign");
    let legacy = root.join("operations/audit");
    copy_trail(&legacy);
    std::fs::write(legacy.join("notes.txt"), "kept by an operator").expect("written");
    let refused = lay_out(
        &volume,
        Some(&legacy),
        AssuranceProfile::Development,
        None,
        1_800_000_000,
    )
    .expect_err("a file beside the chain");
    assert!(refused.to_string().contains("notes.txt"), "{refused}");
    assert!(
        legacy.join("notes.txt").exists(),
        "the legacy directory is left as it was"
    );
    assert!(legacy.join("audit-2026-10-02.jsonl").exists());
    drop(volume);
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn a_volume_without_a_legacy_trail_is_declared_at_version_2() {
    let (root, volume) = claimed("fresh");
    assert!(!needs_migration(&volume, Some(&root.join("operations/audit"))).expect("read"));
    assert_eq!(
        lay_out(
            &volume,
            Some(&root.join("operations/audit")),
            AssuranceProfile::Production,
            None,
            1_800_000_000
        )
        .expect("declared"),
        Laid::Fresh
    );
    let manifest = Layout::open(&volume, SUBSYSTEM)
        .expect("the layout")
        .manifest()
        .expect("read")
        .expect("declared");
    assert_eq!(manifest.active.version, TARGET_VERSION);
    assert_eq!(manifest.active.directory, target());
    drop(volume);
    let _ = std::fs::remove_dir_all(root);
}

/// A seal over the first `records` records of a chain written by [`synthetic`], signed by the
/// Ed25519 key of `seed`, or unsigned; and the key as a `host.operations` JWK.
fn seal_with(
    dir: &Path,
    day: &str,
    records: u64,
    head: &str,
    seed: Option<[u8; 32]>,
) -> serde_json::Value {
    use ring::signature::{Ed25519KeyPair, KeyPair as _};
    let body = SealBody {
        day: day.to_owned(),
        at: format!("{day}T23:59:59Z"),
        records,
        head: head.to_owned(),
    };
    let mut seal = Seal {
        body,
        kid: None,
        algorithm: None,
        signature: None,
    };
    let mut jwk = serde_json::Value::Null;
    if let Some(seed) = seed {
        let key = Ed25519KeyPair::from_seed_unchecked(&seed).expect("a seed");
        let suite = permguard_objects::crypto::suite::Suite::Ed25519Sha256V1;
        let thumbprint =
            permguard_objects::crypto::thumbprint::jwk_thumbprint(suite, key.public_key().as_ref())
                .expect("a thumbprint");
        let signature = key.sign(&seal.signed_bytes().expect("bytes"));
        seal.kid = Some(thumbprint.clone());
        seal.algorithm = Some("EdDSA".to_owned());
        seal.signature = Some(hex(signature.as_ref()));
        use base64::Engine as _;
        jwk = serde_json::json!({
            "kid": format!("host.operations:{thumbprint}"),
            "kty": "OKP",
            "crv": "Ed25519",
            "x": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(key.public_key().as_ref()),
            "alg": "EdDSA",
            "use": "sig",
        });
    }
    std::fs::write(
        dir.join(format!("audit-{day}.seal")),
        serde_json::to_vec(&seal).expect("json"),
    )
    .expect("written");
    jwk
}

/// The digests of the records of `day` in `dir`, in order.
fn digests(dir: &Path, day: &str) -> Vec<String> {
    std::fs::read_to_string(dir.join(format!("audit-{day}.jsonl")))
        .expect("read")
        .lines()
        .map(|line| {
            serde_json::from_str::<Record>(line)
                .expect("a record")
                .digest
        })
        .collect()
}

#[test]
fn a_replaced_record_with_its_number_kept_breaks_the_chain() {
    let dir = scratch("replaced");
    synthetic(&dir, &[1, 2, 3]);
    // Record 2 replaced by one of the same number that does not chain to record 1.
    let path = dir.join("audit-2026-10-03.jsonl");
    let mut lines: Vec<String> = std::fs::read_to_string(&path)
        .expect("read")
        .lines()
        .map(str::to_owned)
        .collect();
    let mut record: Record = serde_json::from_str(&lines[1]).expect("a record");
    record.body.prev = "f".repeat(64);
    record.digest = Record::expected_digest(&record.body).expect("digest");
    lines[1] = serde_json::to_string(&record).expect("json");
    std::fs::write(&path, lines.join("\n") + "\n").expect("written");
    let refused = verify(&dir, None).expect_err("the link is broken");
    assert!(refused.contains("does not follow"), "{refused}");
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn a_chain_rewritten_whole_stops_agreeing_with_its_seal() {
    let dir = scratch("rewritten");
    synthetic(&dir, &[1, 2, 3]);
    seal_with(&dir, "2026-10-03", 3, &"0".repeat(64), None);
    let refused = verify(&dir, None).expect_err("the seal names another head");
    assert!(
        refused.contains("rewritten since they were sealed"),
        "{refused}"
    );
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn the_chain_continues_across_days_and_an_empty_or_foreign_directory_reads() {
    let dir = scratch("two-days");
    synthetic(&dir, &[1, 2]);
    // The next day continues the chain from the first day's last record.
    let first = digests(&dir, "2026-10-03");
    let body = Body {
        seq: 3,
        at: "2026-10-04T00:00:00Z".to_owned(),
        prev: first[1].clone(),
        action: "server.stop".to_owned(),
        subject: "default".to_owned(),
        subject_kind: "system".to_owned(),
        subject_sensitivity: "public".to_owned(),
        target: None,
        continuity_id: None,
        continuity_position: None,
        service: "permguard".to_owned(),
        version: "0.1.0".to_owned(),
    };
    let digest = Record::expected_digest(&body).expect("digest");
    std::fs::write(
        dir.join("audit-2026-10-04.jsonl"),
        serde_json::to_string(&Record { body, digest }).expect("json") + "\n",
    )
    .expect("written");
    std::fs::write(dir.join("notes.txt"), "an operator's").expect("written");
    let verified = verify(&dir, None).expect("verifies across days");
    assert_eq!((verified.records, verified.days), (3, 2));
    let _ = std::fs::remove_dir_all(dir);
    let empty = scratch("empty");
    std::fs::create_dir_all(&empty).expect("created");
    assert!(!holds_chain(&empty));
    assert_eq!(verify(&empty, None).expect("an empty chain").records, 0);
    let _ = std::fs::remove_dir_all(empty);
}

#[test]
fn a_seal_by_a_revoked_key_stands_only_where_a_later_one_covers_it() {
    let dir = scratch("revoked-covered");
    synthetic(&dir, &[1, 2]);
    let head = digests(&dir, "2026-10-03");
    let old = seal_with(&dir, "2026-10-03", 2, &head[1], Some([3; 32]));
    let revoked_kid = old["kid"].as_str().expect("kid").to_owned();
    let only_old = Keys::from_document(
        &serde_json::json!({ "keys": [old.clone()], "revoked": [{ "kid": revoked_kid }] })
            .to_string(),
    )
    .expect("keys");
    let refused = verify(&dir, Some(&only_old)).expect_err("nothing later covers it");
    assert!(refused.contains("revoked since"), "{refused}");
    // A second day sealed by another key that is not revoked covers it.
    let body = Body {
        seq: 3,
        at: "2026-10-04T00:00:00Z".to_owned(),
        prev: head[1].clone(),
        action: "server.stop".to_owned(),
        subject: "default".to_owned(),
        subject_kind: "system".to_owned(),
        subject_sensitivity: "public".to_owned(),
        target: None,
        continuity_id: None,
        continuity_position: None,
        service: "permguard".to_owned(),
        version: "0.1.0".to_owned(),
    };
    let digest = Record::expected_digest(&body).expect("digest");
    std::fs::write(
        dir.join("audit-2026-10-04.jsonl"),
        serde_json::to_string(&Record {
            body,
            digest: digest.clone(),
        })
        .expect("json")
            + "\n",
    )
    .expect("written");
    let new = seal_with(&dir, "2026-10-04", 3, &digest, Some([4; 32]));
    let both = Keys::from_document(
        &serde_json::json!({ "keys": [old, new], "revoked": [{ "kid": revoked_kid }] }).to_string(),
    )
    .expect("keys");
    let verified = verify(&dir, Some(&both)).expect("covered");
    assert!(
        verified
            .warnings
            .iter()
            .any(|warning| warning.contains("covers it")),
        "{:?}",
        verified.warnings
    );
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn a_seal_with_part_of_a_signature_or_named_for_another_day_or_twice_is_refused() {
    let dir = scratch("seal-shapes");
    synthetic(&dir, &[1, 2]);
    let head = digests(&dir, "2026-10-03");
    let path = dir.join("audit-2026-10-03.seal");
    seal_with(&dir, "2026-10-03", 2, &head[1], None);
    let mut seal: Seal =
        serde_json::from_slice(&std::fs::read(&path).expect("read")).expect("seal");
    seal.kid = Some("A".repeat(43));
    std::fs::write(&path, serde_json::to_vec(&seal).expect("json")).expect("written");
    let refused = verify(&dir, None).expect_err("a kid without a signature");
    assert!(refused.contains("part of a signature"), "{refused}");
    seal.kid = None;
    seal.body.day = "2026-10-02".to_owned();
    std::fs::write(&path, serde_json::to_vec(&seal).expect("json")).expect("written");
    let refused = verify(&dir, None).expect_err("named for another day");
    assert!(refused.contains("named for another"), "{refused}");
    seal.body.day = "2026-10-03".to_owned();
    std::fs::write(&path, serde_json::to_vec(&seal).expect("json")).expect("written");
    let mut twin = seal.clone();
    twin.body.day = "2026-10-04".to_owned();
    std::fs::write(
        dir.join("audit-2026-10-04.seal"),
        serde_json::to_vec(&twin).expect("json"),
    )
    .expect("written");
    let refused = verify(&dir, None).expect_err("two seals of one record");
    assert!(refused.contains("same record"), "{refused}");
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn a_day_spelled_twice_or_past_the_last_number_is_refused() {
    let dir = scratch("spellings");
    synthetic(&dir, &[1]);
    std::fs::copy(
        dir.join("audit-2026-10-03.jsonl"),
        dir.join("audit-+2026-10-03.jsonl"),
    )
    .expect("copied");
    let refused = verify(&dir, None);
    // A spelling the date reader accepts names the same day twice; one it refuses is not a day.
    if day_of_file("audit-+2026-10-03.jsonl").is_some() {
        assert!(
            refused
                .as_ref()
                .is_err_and(|error| error.contains("same day")),
            "{refused:?}"
        );
    }
    let _ = std::fs::remove_dir_all(dir);
    let last = scratch("last-number");
    synthetic(&last, &[u64::MAX]);
    let refused = verify(&last, None).expect_err("no number follows it");
    assert!(refused.contains("past the last"), "{refused}");
    let _ = std::fs::remove_dir_all(last);
}

#[test]
fn a_chain_found_once_the_layout_is_at_version_2_is_refused() {
    let (root, volume) = claimed("orphan");
    let legacy = root.join("operations/audit");
    // Declared fresh at a start that found nothing.
    assert_eq!(
        lay_out(
            &volume,
            Some(&legacy),
            AssuranceProfile::Development,
            None,
            1_800_000_000
        )
        .expect("declared"),
        Laid::Fresh
    );
    // The chain is copied in afterwards: it is never silently left behind.
    copy_trail(&legacy);
    let refused = needs_migration(&volume, Some(&legacy)).expect_err("an orphaned chain");
    assert!(
        refused.to_string().contains("not migrated twice"),
        "{refused}"
    );
    assert!(
        lay_out(
            &volume,
            Some(&legacy),
            AssuranceProfile::Development,
            None,
            1_800_000_000
        )
        .is_err()
    );
    drop(volume);
    let _ = std::fs::remove_dir_all(root);

    // The old generation a migration keeps until `finalize` is not an orphan.
    let (root, volume) = claimed("kept");
    let legacy = root.join("operations/audit");
    copy_trail(&legacy);
    lay_out(
        &volume,
        Some(&legacy),
        AssuranceProfile::Development,
        None,
        1_800_000_000,
    )
    .expect("migrated");
    assert!(!needs_migration(&volume, Some(&legacy)).expect("the kept generation"));
    drop(volume);
    let _ = std::fs::remove_dir_all(root);
}

#[cfg(unix)]
#[test]
fn a_link_in_the_legacy_directory_stops_the_migration() {
    let (root, volume) = claimed("link");
    let legacy = root.join("operations/audit");
    copy_trail(&legacy);
    std::os::unix::fs::symlink(root.join("elsewhere"), legacy.join("pointer")).expect("linked");
    let refused = lay_out(
        &volume,
        Some(&legacy),
        AssuranceProfile::Development,
        None,
        1_800_000_000,
    )
    .expect_err("a link beside the chain");
    assert!(refused.to_string().contains("pointer"), "{refused}");
    drop(volume);
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn a_seal_of_records_retention_removed_is_stated_and_not_checked() {
    let dir = scratch("seal-below");
    synthetic(&dir, &[5, 6, 7]);
    seal_with(&dir, "2026-10-02", 3, &"0".repeat(64), None);
    let verified = verify(&dir, None).expect("verifies");
    assert!(
        verified
            .warnings
            .iter()
            .any(|warning| warning.contains("retention removed")),
        "{:?}",
        verified.warnings
    );
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn a_file_over_its_bound_is_refused_before_it_is_read() {
    let dir = scratch("bound");
    synthetic(&dir, &[1]);
    std::fs::write(
        dir.join("audit-2026-10-03.seal"),
        vec![b' '; usize::try_from(MAX_SEAL_BYTES).expect("fits") + 1],
    )
    .expect("written");
    let refused = verify(&dir, None).expect_err("over the bound");
    assert!(refused.contains("more than"), "{refused}");
    let _ = std::fs::remove_dir_all(dir);
}
