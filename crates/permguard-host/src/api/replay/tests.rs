// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::expect_used)]

use super::files::{COMPACTING, FileReplay, SUPERSEDED, State, StoredResult, remember};
use super::*;
use crate::api::testing::scratch;
use crate::storage::journal::{Journal, Options};
use crate::storage::volume::Volume;
use permguard_core::assurance::AssuranceProfile;

/// The window of `volume` on the file backend, and the backend itself for what only it does.
fn opened(volume: &Volume, now: u64) -> (Replay, Arc<FileReplay>) {
    let (files, _) = FileReplay::open(volume, now).expect("the replay opens");
    let files = Arc::new(files);
    (
        Replay::new(Arc::clone(&files) as Arc<dyn ReplayStore>),
        files,
    )
}

fn principal(name: &str) -> Principal {
    Principal::new(name).expect("a principal")
}

#[test]
fn a_result_is_replayed_for_the_same_request_and_refused_for_another() {
    let root = scratch("replay-same");
    let volume = Volume::claim(&root, AssuranceProfile::Development).expect("claimed");
    let (replay, files) = opened(&volume, 1_000);
    let alice = principal("alice");
    assert!(
        replay
            .lookup::<u64>(&alice, "r1", "op", "d1")
            .expect("looked up")
            .is_none()
    );
    files
        .record(&alice, "r1", "op", "d1", &42u64)
        .expect("recorded");
    assert_eq!(
        replay.lookup::<u64>(&alice, "r1", "op", "d1").expect("ok"),
        Some(42)
    );
    let reused = replay
        .lookup::<u64>(&alice, "r1", "op", "d2")
        .expect_err("another request under the same id");
    assert_eq!(
        reused.error().expect("refusal").code(),
        codes::host::REQUEST_ID_REUSED
    );
    let other_op = replay
        .lookup::<u64>(&alice, "r1", "other", "d1")
        .expect_err("another operation under the same id");
    assert_eq!(
        other_op.error().expect("refusal").code(),
        codes::host::REQUEST_ID_REUSED
    );
    // Another principal's namespace is its own.
    assert!(
        replay
            .lookup::<u64>(&principal("bob"), "r1", "op", "d1")
            .expect("ok")
            .is_none()
    );
}

#[test]
fn a_result_survives_a_restart_and_an_expired_one_is_compacted_away() {
    let root = scratch("replay-restart");
    let alice = principal("alice");
    {
        let volume = Volume::claim(&root, AssuranceProfile::Development).expect("claimed");
        let (_, files) = opened(&volume, 1_000);
        files
            .record(&alice, "r1", "op", "d1", &"first")
            .expect("recorded");
    }
    {
        let volume = Volume::claim(&root, AssuranceProfile::Development).expect("claimed");
        let now = permguard_core::time::unix_now();
        let (replay, _) = opened(&volume, now);
        assert_eq!(
            replay.held().expect("the results read"),
            1,
            "the result is read back from the journal"
        );
        assert_eq!(
            replay
                .lookup::<String>(&alice, "r1", "op", "d1")
                .expect("ok"),
            Some("first".to_owned())
        );
    }
    {
        let volume = Volume::claim(&root, AssuranceProfile::Development).expect("claimed");
        let far = permguard_core::time::unix_now() + WINDOW.as_secs() + 1;
        let (replay, _) = opened(&volume, far);
        assert_eq!(
            replay.held().expect("the results read"),
            0,
            "past the window nothing is held"
        );
        let state_dir = volume.host().subdir(DIRECTORY, false).expect("state");
        let names = state_dir.subdirs().expect("listed");
        assert_eq!(
            names,
            vec![JOURNAL.to_owned()],
            "the swap left only the journal"
        );
        // And the rewritten journal holds no result frame.
        let journal_dir = state_dir.subdir(JOURNAL, false).expect("journal");
        let (journal, _) = Journal::open(journal_dir, volume.journal_options(Options::default()))
            .expect("the rewritten journal opens");
        assert!(journal.frames().expect("frames").is_empty());
    }
}

#[test]
fn the_per_principal_cap_drops_the_oldest() {
    let mut state = State::default();
    for index in 0..=PER_PRINCIPAL {
        remember(
            &mut state,
            StoredResult {
                principal: "alice".to_owned(),
                request_id: format!("r{index}"),
                operation: "op".to_owned(),
                digest: "d".to_owned(),
                result: serde_json::Value::Null,
                recorded_at: 0,
            },
        );
    }
    assert_eq!(state.results.len(), PER_PRINCIPAL);
    assert!(
        !state
            .results
            .contains_key(&("alice".to_owned(), "r0".to_owned())),
        "the oldest went"
    );
    assert!(
        state
            .results
            .contains_key(&("alice".to_owned(), format!("r{PER_PRINCIPAL}")))
    );
}

#[test]
fn a_plan_is_consumed_once_and_expires() {
    let root = scratch("replay-plan");
    let volume = Volume::claim(&root, AssuranceProfile::Development).expect("claimed");
    let (replay, _) = opened(&volume, 1_000);
    let alice = principal("alice");
    let plan = Plan {
        plan_id: "p1".to_owned(),
        operation: "grants.revoke".to_owned(),
        target: "g1".to_owned(),
        revision: 3,
        digest: "abc".to_owned(),
        expires: 2_000,
        principal: "alice".to_owned(),
        ..Plan::default()
    };
    replay
        .plan(&Applying::for_tests(1), plan.clone())
        .expect("planned");
    assert_eq!(replay.plan_of(&alice, "p1", 1_500).expect("held"), plan);
    let expired = replay.plan_of(&alice, "p1", 2_000).expect_err("expired");
    assert_eq!(
        expired.error().expect("refusal").code(),
        codes::host::PLAN_EXPIRED
    );
    let unknown = replay
        .plan_of(&principal("bob"), "p1", 1_500)
        .expect_err("not bob's");
    assert_eq!(
        unknown.error().expect("refusal").code(),
        codes::host::PLAN_UNKNOWN
    );
    replay
        .consume(&Applying::for_tests(2), &alice, "p1")
        .expect("consumed");
    let again = replay.plan_of(&alice, "p1", 1_500).expect_err("consumed");
    assert_eq!(
        again.error().expect("refusal").code(),
        codes::host::PLAN_EXPIRED
    );
    drop(replay);
    // Consumption survives a restart.
    let (replay, _) = opened(&volume, 1_500);
    let again = replay
        .plan_of(&alice, "p1", 1_500)
        .expect_err("still consumed");
    assert_eq!(
        again.error().expect("refusal").code(),
        codes::host::PLAN_EXPIRED
    );
}

/// An approval and a consumption ahead of the change are operations of the plans domain:
/// recovery finds each by what it wrote (WP-3.9), and an approval survives a restart.
#[test]
fn an_approval_survives_a_restart_and_recovery_finds_it_by_its_operation() {
    let root = scratch("replay-approval");
    let volume = Volume::claim(&root, AssuranceProfile::Development).expect("claimed");
    let (replay, _) = opened(&volume, 1_000);
    let alice = principal("alice");
    let plan = Plan {
        plan_id: "p1".to_owned(),
        operation: "identity.reset".to_owned(),
        target: "t".to_owned(),
        revision: 3,
        digest: "abc".to_owned(),
        expires: 2_000,
        principal: "alice".to_owned(),
        kind: "identity.reset".to_owned(),
        approvals_required: 1,
        ..Plan::default()
    };
    replay
        .plan(&Applying::for_tests(1), plan.clone())
        .expect("planned");
    let approving = Applying::for_tests(2);
    let approval = PlanApproval {
        principal: "bob".to_owned(),
        approved_at: 1_100,
        envelope: "e".to_owned(),
        operation_id: approving.operation_id().to_string(),
        token: None,
    };
    replay
        .approve(&approving, "p1", &|_, _| Ok(approval.clone()))
        .expect("approved");
    drop(replay);

    let (replay, _) = opened(&volume, 1_200);
    assert_eq!(
        replay.plan_of(&alice, "p1", 1_200).expect("held").approvals,
        vec![approval]
    );
    assert_eq!(replay.name(), DOMAIN);
    let found = replay
        .observe(&approving.operation_id(), Some("p1"))
        .expect("the domain answers")
        .expect("the approval is found");
    assert_eq!(found.revision, 3);
    assert!(
        replay
            .observe(&Applying::for_tests(3).operation_id(), Some("p1"))
            .expect("the domain answers")
            .is_none(),
        "an operation that wrote nothing is not found"
    );
    assert!(
        replay
            .observe(&approving.operation_id(), None)
            .expect("the domain answers")
            .is_none()
    );
    assert!(
        replay
            .observe(&Applying::for_tests(4).operation_id(), Some("consume:p1"))
            .expect("the domain answers")
            .is_none(),
        "not consumed yet"
    );
    replay
        .consume(&Applying::for_tests(4), &alice, "p1")
        .expect("consumed");
    assert!(
        replay
            .observe(&Applying::for_tests(4).operation_id(), Some("consume:p1"))
            .expect("the domain answers")
            .is_some()
    );
}

/// An expired plan is kept one window past its expiry, so the plans store lists it, then goes.
#[test]
fn an_expired_plan_is_listed_for_one_window_then_dropped() {
    let root = scratch("replay-expired");
    let volume = Volume::claim(&root, AssuranceProfile::Development).expect("claimed");
    let (replay, _) = opened(&volume, 1_000);
    let plan = Plan {
        plan_id: "p1".to_owned(),
        operation: "grants.revoke".to_owned(),
        target: "g1".to_owned(),
        expires: 2_000,
        principal: "alice".to_owned(),
        kind: "grant.revoke".to_owned(),
        ..Plan::default()
    };
    replay.plan(&Applying::for_tests(1), plan).expect("planned");
    drop(replay);
    let within = 2_000 + WINDOW.as_secs() - 1;
    let (replay, _) = opened(&volume, within);
    assert_eq!(
        replay.plans().expect("the plans read").len(),
        1,
        "listed while expired"
    );
    assert!(replay.plan_of(&principal("alice"), "p1", within).is_err());
    drop(replay);
    let (replay, _) = opened(&volume, 2_000 + WINDOW.as_secs());
    assert!(replay.plans().expect("the plans read").is_empty());
}

#[test]
fn a_consumed_plan_stays_consumed_across_a_compaction() {
    let root = scratch("replay-consumed-compact");
    let alice = principal("alice");
    let plan = Plan {
        plan_id: "p1".to_owned(),
        operation: "grants.revoke".to_owned(),
        target: "g1".to_owned(),
        revision: 1,
        digest: "d".to_owned(),
        expires: permguard_core::time::unix_now() + 3_600,
        principal: "alice".to_owned(),
        ..Plan::default()
    };
    {
        let volume = Volume::claim(&root, AssuranceProfile::Development).expect("claimed");
        let (replay, files) = opened(&volume, 1_000);
        replay.plan(&Applying::for_tests(1), plan).expect("planned");
        replay
            .consume(&Applying::for_tests(2), &alice, "p1")
            .expect("consumed");
        // An expired result, so the next open compacts.
        files
            .record(&alice, "old", "op", "d", &1u8)
            .expect("recorded");
    }
    let volume = Volume::claim(&root, AssuranceProfile::Development).expect("claimed");
    let far = permguard_core::time::unix_now() + WINDOW.as_secs() + 1;
    let (replay, files) = opened(&volume, far);
    assert_eq!(replay.held().expect("the results read"), 0);
    let again = replay
        .plan_of(&alice, "p1", far)
        .expect_err("consumed, and still said so");
    assert_eq!(
        again.error().expect("refusal").code(),
        codes::host::PLAN_EXPIRED
    );
    // The journal reopened where it lives: a write after the swap lands and is durable.
    files
        .record(&alice, "new", "op", "d", &2u8)
        .expect("the compacted journal takes a write");
    drop(replay);
    let (replay, _) = opened(&volume, permguard_core::time::unix_now());
    assert_eq!(
        replay.held().expect("the results read"),
        1,
        "the write after the compaction is durable"
    );
    let state_dir = volume.host().subdir(DIRECTORY, false).expect("state");
    assert_eq!(
        state_dir.subdirs().expect("listed"),
        vec![JOURNAL.to_owned()],
        "no swap directory is left behind"
    );
}

#[test]
fn a_second_arrival_of_a_request_in_flight_is_refused_until_the_first_answers() {
    let root = scratch("replay-in-flight");
    let volume = Volume::claim(&root, AssuranceProfile::Development).expect("claimed");
    let (replay, _) = opened(&volume, 1_000);
    let alice = principal("alice");
    let first = replay.begin(&alice, "r1").expect("the first is in flight");
    let second = replay
        .begin(&alice, "r1")
        .expect_err("the same pair, while in flight");
    assert_eq!(
        second.error().expect("refusal").code(),
        codes::host::REQUEST_IN_FLIGHT
    );
    assert!(
        replay.begin(&principal("bob"), "r1").is_ok(),
        "another principal's pair"
    );
    drop(first);
    drop(replay.begin(&alice, "r1").expect("free again"));
}

#[test]
fn a_half_finished_compaction_is_swept_at_open() {
    let root = scratch("replay-sweep");
    let volume = Volume::claim(&root, AssuranceProfile::Development).expect("claimed");
    let alice = principal("alice");
    {
        let (_, files) = opened(&volume, 1_000);
        files
            .record(&alice, "r1", "op", "d1", &1u8)
            .expect("recorded");
    }
    let state_dir = volume.host().subdir(DIRECTORY, false).expect("state");
    // A crash after the first rename: the journal is aside, nothing replaced it.
    state_dir
        .rename(JOURNAL, SUPERSEDED)
        .expect("renamed aside");
    state_dir
        .subdir(COMPACTING, true)
        .expect("a compaction had begun");
    let (replay, _) = opened(&volume, 1_000);
    assert_eq!(
        replay.held().expect("the results read"),
        1,
        "the journal renamed aside was put back"
    );
    assert_eq!(
        state_dir.subdirs().expect("listed"),
        vec![JOURNAL.to_owned()]
    );
}

#[test]
fn the_digest_follows_the_request_and_ids_are_distinct() {
    #[derive(Serialize)]
    struct Body {
        a: u8,
    }
    assert_eq!(
        digest_of(&Body { a: 1 }).expect("digest"),
        digest_of(&Body { a: 1 }).expect("digest")
    );
    assert_ne!(
        digest_of(&Body { a: 1 }).expect("digest"),
        digest_of(&Body { a: 2 }).expect("digest")
    );
    assert_ne!(mint_id().expect("minted"), mint_id().expect("minted"));
    assert_eq!(mint_id().expect("minted").len(), 32);
}

/// The file backend passes the contract's suite, each case on a window of its own and every
/// change inside an operation the engine built.
#[test]
fn the_file_backend_keeps_the_contract() {
    use crate::operations::journal::Initiator;
    use crate::operations::mutation::{Applied, Begin, Failure, Mutations};
    use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

    let engine_volume = Volume::claim(
        &scratch("replay-suite-engine"),
        AssuranceProfile::Development,
    )
    .expect("claimed");
    let mutations = Mutations::open_offline(&engine_volume, "suite").expect("the engine opens");
    let made = AtomicUsize::new(0);
    let next = AtomicU64::new(1);
    // The volumes stay claimed while their stores are used.
    let volumes = Mutex::new(Vec::new());
    suite::run(
        &|| {
            let case = made.fetch_add(1, Ordering::Relaxed);
            let volume = Volume::claim(
                &scratch(&format!("replay-suite-{case}")),
                AssuranceProfile::Development,
            )
            .expect("claimed");
            let (store, _) = FileReplay::open(&volume, 1_000).expect("the replay opens");
            volumes.lock().expect("lock").push(volume);
            Arc::new(store)
        },
        &|work| {
            let at = next.fetch_add(1, Ordering::Relaxed);
            mutations
                .run(
                    Begin {
                        domain: DOMAIN,
                        operation: "suite.operation",
                        action: crate::api::plans::AUDIT_APPROVED,
                        initiator: Initiator::System("suite".to_owned()),
                        request: None,
                        target: Some(format!("suite-{at}")),
                    },
                    |applying| {
                        work(applying);
                        Ok::<_, Failure<String>>(Applied {
                            revision: at,
                            target: None,
                            value: (),
                        })
                    },
                )
                .expect("the operation runs");
        },
    );
}
