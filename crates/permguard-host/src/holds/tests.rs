// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::expect_used)]

use std::sync::{Arc, Mutex};
use std::time::Duration;

use permguard_core::AuditEvent;
use permguard_core::assurance::AssuranceProfile;

use super::*;
use crate::operations::mutation::Projection;
use crate::time::{ManualClock, ManualMonotonic, TimeGuard};

const NOW: u64 = 1_800_000_000;
const ZONE: &str = "01a00000-0000-7000-8000-00000000000a";
const LEDGER: &str = "01a00000-0000-7000-8000-00000000000b";
const OTHER: &str = "01a00000-0000-7000-8000-00000000000c";

fn scratch(tag: &str) -> std::path::PathBuf {
    let path = std::env::temp_dir().join(format!(
        "permguard-host-holds-{tag}-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&path);
    path
}

/// One projected record: action, phase, target, and the whole event.
type Projected = (String, &'static str, Option<String>, String);

/// Every record the transaction projects.
#[derive(Default)]
struct Trail(Mutex<Vec<Projected>>);

impl Projection for Trail {
    fn project(&self, event: &AuditEvent<'_>) -> Result<(), String> {
        let (_, phase) = event.operation().expect("every record names its operation");
        self.0.lock().expect("lock").push((
            event.action().to_owned(),
            phase.as_str(),
            event.target().map(str::to_owned),
            format!("{event:?}"),
        ));
        Ok(())
    }
}

fn open(tag: &str) -> (Volume, HoldStore, Mutations, Arc<Trail>) {
    let volume =
        Volume::claim(&scratch(tag), AssuranceProfile::Development).expect("a test volume");
    let store = HoldStore::open(&volume).expect("the holds open");
    let trail = Arc::new(Trail::default());
    let time = Arc::new(TimeGuard::new(
        Arc::new(ManualClock::at(NOW as i64)),
        Arc::new(ManualMonotonic::default()),
        Duration::from_secs(30),
    ));
    let mutations = Mutations::open(&volume, Arc::clone(&trail) as Arc<dyn Projection>, time)
        .expect("the journal opens");
    (volume, store, mutations, trail)
}

fn ledger() -> String {
    format!("plane/control/zone/{ZONE}/ledger/{LEDGER}")
}

fn new_hold(resource: String, deadline: Deadline) -> NewHold {
    NewHold {
        resource,
        owner: "legal@acme".to_owned(),
        reason: "litigation 2026-17".to_owned(),
        deadline,
    }
}

/// WP-7.3c, owner decisions of 2026-10-21: a hold is a file of its own under `host/holds/`,
/// listed and read back by its id, and its release removes it.
#[test]
fn a_hold_is_written_listed_and_released() {
    let (volume, store, mutations, _) = open("lifecycle");
    let added = add(
        &mutations,
        &store,
        Initiator::System("cli".to_owned()),
        new_hold(ledger(), Deadline::Review(NOW + 86_400)),
        NOW,
    )
    .expect("added");
    assert!(is_guid_shaped(&added.id));
    assert_eq!(
        (added.review_at, added.expires_at),
        (Some(NOW + 86_400), None)
    );
    assert!(
        volume
            .host()
            .path()
            .join(DIRECTORY)
            .join(format!("{}.json", added.id))
            .is_file()
    );
    assert_eq!(store.list().expect("lists"), vec![added.clone()]);
    assert_eq!(store.get(&added.id).expect("reads"), Some(added.clone()));
    assert!(store.keeps(ZONE, LEDGER, NOW).expect("reads"));
    assert!(!store.keeps(ZONE, OTHER, NOW).expect("reads"));

    let released = release(
        &mutations,
        &store,
        Initiator::System("cli".to_owned()),
        &added.id,
    )
    .expect("released");
    assert_eq!(released.id, added.id);
    assert!(store.list().expect("lists").is_empty());
    assert!(matches!(
        release(
            &mutations,
            &store,
            Initiator::System("cli".to_owned()),
            &added.id
        ),
        Err(MutationError::Refused(HoldError::NotFound(_)))
    ));
    // A name or a path is no id: it forms no file name.
    assert_eq!(store.get("../x").expect("reads"), None);
}

/// WP-7.3c, owner decision of 2026-10-21: a hold names a zone or a ledger of the Control Plane
/// by ids, an owner and a reason, and exactly one deadline, in the future.
#[test]
fn a_hold_names_ids_and_exactly_one_deadline() {
    let later = Deadline::Expires(NOW + 1);
    assert!(validate(&new_hold(ledger(), later), NOW).is_ok());
    assert!(validate(&new_hold(format!("plane/control/zone/{ZONE}"), later), NOW).is_ok());
    for resource in [
        "plane/control/zone/delivery/ledger/policies".to_owned(),
        format!("plane/data/zone/{ZONE}/ledger/{LEDGER}"),
        "plane/control".to_owned(),
        "host".to_owned(),
        format!("plane/control/zone/{ZONE}/ledger/../x"),
        // The catalog mints lowercase ids, and a hold compares them byte for byte (after the
        // review): an upper-case one would hold nothing.
        format!("plane/control/zone/{}/ledger/{LEDGER}", ZONE.to_uppercase()),
    ] {
        assert!(
            matches!(
                validate(&new_hold(resource.clone(), later), NOW),
                Err(HoldError::Invalid(_))
            ),
            "{resource}"
        );
    }
    for (owner, reason) in [
        ("", "why"),
        ("who", "   "),
        ("who", "line\nbreak"),
        ("who", &*"x".repeat(MAX_TEXT + 1)),
        ("who\u{202e}", "why"),
        ("who", "zero\u{200b}width"),
    ] {
        let mut hold = new_hold(ledger(), later);
        hold.owner = owner.to_owned();
        hold.reason = reason.to_owned();
        assert!(validate(&hold, NOW).is_err(), "{owner:?} {reason:?}");
    }
    for past in [
        Deadline::Expires(NOW),
        Deadline::Review(NOW - 1),
        Deadline::Expires(253_402_300_800),
    ] {
        assert!(
            validate(&new_hold(ledger(), past), NOW).is_err(),
            "{past:?}"
        );
    }
}

/// WP-7.3c, after the review: a hold's file is read whole or refused, whatever wrote it: closed,
/// bounded, by lowercase ids, with exactly one deadline.
#[test]
fn a_hold_file_that_breaks_the_rules_does_not_read() {
    let (volume, store, _, _) = open("rules");
    let path = volume
        .host()
        .path()
        .join(DIRECTORY)
        .join(format!("{OTHER}.json"));
    let hold = |extra: serde_json::Value| {
        let mut hold = serde_json::json!({
            "id": OTHER, "resource": ledger(), "owner": "o", "reason": "r", "created_at": NOW,
        });
        for (key, value) in extra.as_object().expect("an object") {
            hold[key] = value.clone();
        }
        hold.to_string()
    };
    std::fs::write(&path, hold(serde_json::json!({"review_at": NOW + 1}))).expect("written");
    assert_eq!(store.list().expect("a sound hold reads").len(), 1);
    for broken in [
        hold(serde_json::json!({"review_at": NOW + 1, "expires_at": NOW + 1})),
        hold(serde_json::json!({})),
        hold(serde_json::json!({"review_at": NOW + 1, "extra": 1})),
        hold(serde_json::json!({"review_at": NOW + 1, "resource": "plane/control/zone/delivery"})),
        hold(serde_json::json!({"review_at": NOW + 1, "owner": "\u{202e}"})),
        hold(serde_json::json!({"review_at": u64::MAX})),
        hold(serde_json::json!({"review_at": NOW + 1, "reason": "x".repeat(9 * 1024)})),
    ] {
        std::fs::write(&path, &broken).expect("written");
        assert!(
            matches!(store.list(), Err(HoldError::Record(_))),
            "{broken}"
        );
    }
    // A sound hold, padded past the bound: refused for its size alone.
    let padded = format!(
        "{}{}",
        hold(serde_json::json!({"review_at": NOW + 1})),
        " ".repeat(9 * 1024)
    );
    std::fs::write(&path, &padded).expect("written");
    assert!(
        matches!(store.list(), Err(HoldError::Record(_))),
        "padded"
    );
}

/// WP-7.3c, owner decision of 2026-10-21: past `expires_at` a hold keeps nothing; past
/// `review_at` it keeps and is due for review; a zone's hold keeps every ledger of the zone.
#[test]
fn an_expired_hold_keeps_nothing_and_one_past_review_still_keeps() {
    let hold = |resource: String, expires_at, review_at| Hold {
        id: OTHER.to_owned(),
        resource,
        owner: "o".to_owned(),
        reason: "r".to_owned(),
        created_at: NOW,
        expires_at,
        review_at,
        operation: None,
    };
    let expiring = hold(ledger(), Some(NOW + 10), None);
    assert_eq!(expiring.status(NOW), Status::Active);
    assert!(expiring.keeps(ZONE, LEDGER, NOW + 9));
    assert_eq!(expiring.status(NOW + 10), Status::Expired);
    assert!(!expiring.keeps(ZONE, LEDGER, NOW + 10));

    let reviewed = hold(ledger(), None, Some(NOW + 10));
    assert_eq!(reviewed.status(NOW + 10), Status::ReviewDue);
    assert!(reviewed.keeps(ZONE, LEDGER, NOW + 1_000_000));
    assert!(!reviewed.keeps(ZONE, OTHER, NOW));

    let zone = hold(format!("plane/control/zone/{ZONE}"), None, Some(NOW + 10));
    assert!(zone.keeps(ZONE, LEDGER, NOW));
    assert!(zone.keeps(ZONE, OTHER, NOW));
    assert!(!zone.keeps(OTHER, LEDGER, NOW));
    assert_eq!(Status::ReviewDue.as_str(), "review_due");
}

/// WP-7.3c, owner decision of 2026-10-21: adding and releasing a hold are operations of the
/// transaction, an intent then an applied record under the phased actions, naming the hold's id
/// and resource and never its owner or reason.
#[test]
fn a_hold_change_is_an_operation_of_the_transaction_and_names_no_free_text() {
    let (volume, store, mutations, trail) = open("trail");
    let added = add(
        &mutations,
        &store,
        Initiator::System("cli".to_owned()),
        new_hold(ledger(), Deadline::Expires(NOW + 60)),
        NOW,
    )
    .expect("added");
    release(
        &mutations,
        &store,
        Initiator::System("cli".to_owned()),
        &added.id,
    )
    .expect("released");

    let records = trail.0.lock().expect("lock").clone();
    let phases: Vec<(&str, &str)> = records
        .iter()
        .map(|(action, phase, _, _)| (action.as_str(), *phase))
        .collect();
    assert_eq!(
        phases,
        vec![
            (AUDIT_ADDED, "intent"),
            (AUDIT_ADDED, "applied"),
            (AUDIT_RELEASED, "intent"),
            (AUDIT_RELEASED, "applied"),
        ]
    );
    for (_, _, target, event) in &records {
        let target = target.as_deref().expect("a target");
        assert!(
            target.contains(&added.id) && target.contains(&ledger()),
            "{target}"
        );
        assert!(
            !event.contains("legal@acme") && !event.contains("litigation"),
            "{event}"
        );
    }
    // Nor does the transaction's journal: the hold is released, and no file of the Host's part
    // of the volume holds its free text (after the review).
    fn walk(dir: &std::path::Path, seen: &mut Vec<std::path::PathBuf>) {
        for entry in std::fs::read_dir(dir).expect("lists").flatten() {
            let path = entry.path();
            if path.is_dir() {
                walk(&path, seen);
            } else {
                seen.push(path);
            }
        }
    }
    let mut files = Vec::new();
    walk(volume.host().path(), &mut files);
    for path in files {
        let bytes = std::fs::read(&path).expect("reads");
        let text = String::from_utf8_lossy(&bytes);
        assert!(
            !text.contains("legal@acme") && !text.contains("litigation"),
            "{} keeps the free text",
            path.display()
        );
    }
    // A refused hold begins no operation.
    let refused = add(
        &mutations,
        &store,
        Initiator::System("cli".to_owned()),
        new_hold("host".to_owned(), Deadline::Expires(NOW + 60)),
        NOW,
    );
    assert!(matches!(
        refused,
        Err(MutationError::Refused(HoldError::Invalid(_)))
    ));
    assert_eq!(trail.0.lock().expect("lock").len(), 4);
}

/// WP-7.3c, owner decision of 2026-10-21: a hold's file that does not read is an error, never
/// skipped, so nothing is decided on fewer holds than there are.
#[test]
fn a_hold_that_does_not_read_is_an_error_never_skipped() {
    let (volume, store, _, _) = open("unreadable");
    std::fs::write(
        volume
            .host()
            .path()
            .join(DIRECTORY)
            .join(format!("{OTHER}.json")),
        b"{ not a hold",
    )
    .expect("a broken hold");
    assert!(matches!(store.list(), Err(HoldError::Record(_))));
    assert!(store.keeps(ZONE, LEDGER, NOW).is_err());
}

/// WP-7.3c: recovery shows an add when the hold's file names the operation, and a release when
/// the file is gone.
#[test]
fn recovery_reads_an_add_from_its_file_and_a_release_from_its_absence() {
    let (_volume, store, mutations, _) = open("recovery");
    let added = add(
        &mutations,
        &store,
        Initiator::System("cli".to_owned()),
        new_hold(ledger(), Deadline::Expires(NOW + 60)),
        NOW,
    )
    .expect("added");
    let operation: [u8; 16] = {
        let text = added.operation.clone().expect("the operation");
        let mut bytes = [0u8; 16];
        for (at, byte) in bytes.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&text[at * 2..at * 2 + 2], 16).expect("hex");
        }
        bytes
    };
    let domain = Holds(&store);
    let id = OperationId::from_bytes(operation);
    let target = format!("hold/{}/{}", added.id, ledger());
    assert!(domain.observe(&id, Some(&target)).is_some());
    assert!(
        domain
            .observe(&OperationId::from_bytes([0; 16]), Some(&target))
            .is_none(),
        "another operation's hold"
    );
    let released = format!("released/{}/{}", added.id, ledger());
    assert!(
        domain.observe(&id, Some(&released)).is_none(),
        "still there"
    );
    release(
        &mutations,
        &store,
        Initiator::System("cli".to_owned()),
        &added.id,
    )
    .expect("released");
    assert!(domain.observe(&id, Some(&released)).is_some());
}
