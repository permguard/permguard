// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::expect_used)]

use std::sync::atomic::{AtomicBool, Ordering};

use permguard_core::assurance::AssuranceProfile;

use super::*;
use crate::time::{ManualClock, ManualMonotonic};

const START: i64 = 1_800_000_000;

fn scratch(tag: &str) -> std::path::PathBuf {
    let path = std::env::temp_dir().join(format!(
        "permguard-host-mutations-{tag}-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&path);
    path
}

fn guard() -> (Arc<ManualClock>, Arc<TimeGuard>) {
    let wall = Arc::new(ManualClock::at(START));
    let time = Arc::new(TimeGuard::new(
        wall.clone(),
        Arc::new(ManualMonotonic::default()),
        Duration::from_secs(30),
    ));
    (wall, time)
}

/// One record as the test reads it: action, operation id, phase, target.
type Record = (String, [u8; 16], &'static str, Option<String>);

/// An audit trail that remembers every record, or refuses them all, or those of one phase.
#[derive(Default)]
struct Trail {
    records: Mutex<Vec<Record>>,
    refuse: AtomicBool,
    refuse_phase: Mutex<Option<&'static str>>,
}

impl Projection for Trail {
    fn project(&self, event: &AuditEvent<'_>) -> Result<(), String> {
        let (id, phase) = event.operation().expect("every record names its operation");
        if self.refuse.load(Ordering::SeqCst)
            || *self.refuse_phase.lock().expect("lock") == Some(phase.as_str())
        {
            return Err("the trail is full".to_owned());
        }
        self.records.lock().expect("lock").push((
            event.action().to_owned(),
            *id,
            phase.as_str(),
            event.target().map(str::to_owned),
        ));
        Ok(())
    }
}

impl Trail {
    fn phases(&self) -> Vec<&'static str> {
        self.records
            .lock()
            .expect("lock")
            .iter()
            .map(|record| record.2)
            .collect()
    }
}

/// A domain that keeps what it applied in memory.
#[derive(Default)]
struct Ledger {
    applied: Mutex<BTreeMap<OperationId, Observed>>,
}

impl Domain for Ledger {
    fn name(&self) -> &'static str {
        "ledger"
    }

    fn observe(&self, operation_id: &OperationId) -> Option<Observed> {
        self.applied
            .lock()
            .expect("lock")
            .get(operation_id)
            .cloned()
    }
}

impl Ledger {
    fn apply(&self, applying: &Applying<'_>, target: &str) -> Applied<String> {
        let mut applied = self.applied.lock().expect("lock");
        let revision = applied.len() as u64 + 1;
        applied.insert(
            applying.operation_id(),
            Observed {
                revision,
                target: Some(target.to_owned()),
            },
        );
        Applied {
            revision,
            target: Some(target.to_owned()),
            value: format!("{target}@{revision}"),
        }
    }
}

fn begin(request_id: Option<&str>, digest: &str) -> Begin {
    Begin {
        domain: "ledger",
        operation: "ledger.write",
        action: "host.grant.issued",
        initiator: Initiator::Principal("alice".to_owned()),
        request: request_id.map(|request_id| RequestKey {
            request_id: request_id.to_owned(),
            digest: digest.to_owned(),
        }),
        target: None,
    }
}

fn open(volume: &Volume, trail: &Arc<Trail>, time: &Arc<TimeGuard>) -> Mutations {
    Mutations::open(
        volume,
        Arc::clone(trail) as Arc<dyn Projection>,
        Arc::clone(time),
    )
    .expect("the journal opens")
}

fn entries(volume: &Volume) -> Vec<Entry> {
    let dir = volume
        .host()
        .subdir(crate::audit::DIRECTORY, false)
        .and_then(|dir| dir.subdir(DIRECTORY, false))
        .expect("the directory");
    sequence::read(&dir, JOURNAL, MAX_ENTRY_BYTES)
        .expect("reads")
        .items
        .into_iter()
        .map(|item| Entry::from_value(item).expect("an entry"))
        .collect()
}

#[test]
fn an_operation_runs_every_step_under_one_operation_id() {
    let root = scratch("steps");
    let volume = Volume::claim(&root, AssuranceProfile::Development).expect("claimed");
    let (_, time) = guard();
    let trail = Arc::new(Trail::default());
    let engine = open(&volume, &trail, &time);
    let ledger = Ledger::default();
    let outcome = engine
        .run(begin(Some("r1"), "d1"), |applying| {
            Ok::<_, Failure<String>>(ledger.apply(applying, "z1"))
        })
        .expect("applied");
    assert_eq!(outcome, Outcome::Applied("z1@1".to_owned()));
    let records = trail.records.lock().expect("lock").clone();
    assert_eq!(trail.phases(), vec!["intent", "applied"]);
    assert_eq!(records[0].1, records[1].1, "one operation id");
    assert_eq!(
        records[1].3.as_deref(),
        Some("z1"),
        "the outcome names the target"
    );
    let id = OperationId::from_bytes(records[0].1);
    assert!(ledger.observe(&id).is_some(), "the domain carries it");
    let journal = entries(&volume);
    assert!(matches!(
        &journal[..],
        [Entry::Intent(_), Entry::Commit(_), Entry::Projected { .. }]
    ));
    assert!(journal.iter().all(|entry| entry.operation_id() == id));
    assert_eq!(engine.pending(), 0);
    assert!(engine.open_intents().is_empty());
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn a_retry_learns_the_answer_inside_the_window_and_another_request_is_refused() {
    let root = scratch("retry");
    let volume = Volume::claim(&root, AssuranceProfile::Development).expect("claimed");
    let (wall, time) = guard();
    let trail = Arc::new(Trail::default());
    let ledger = Ledger::default();
    {
        let engine = open(&volume, &trail, &time);
        engine
            .run(begin(Some("r1"), "d1"), |applying| {
                Ok::<_, Failure<String>>(ledger.apply(applying, "z1"))
            })
            .expect("applied");
    }
    // Another process: the answer survives the restart and the snapshot it is folded into.
    let engine = open(&volume, &trail, &time);
    assert!(
        entries(&volume).is_empty(),
        "folded into the snapshot at open"
    );
    let again = engine
        .run(
            begin(Some("r1"), "d1"),
            |_| -> Result<Applied<String>, Failure<String>> {
                panic!("a retry never applies again")
            },
        )
        .expect("replayed");
    assert_eq!(again, Outcome::Replayed("z1@1".to_owned()));
    let reused = engine
        .run(
            begin(Some("r1"), "other"),
            |_| -> Result<Applied<String>, Failure<String>> { panic!("refused before it applies") },
        )
        .expect_err("another request under the same id");
    assert!(matches!(reused, MutationError::RequestIdReused(_)));
    assert_eq!(trail.phases().len(), 2, "a retry records nothing");
    // Past the window the id is free again.
    wall.jump(i64::try_from(WINDOW.as_secs()).expect("fits") + 1);
    let later = engine
        .run(begin(Some("r1"), "other"), |applying| {
            Ok::<_, Failure<String>>(ledger.apply(applying, "z2"))
        })
        .expect("a new operation");
    assert_eq!(later, Outcome::Applied("z2@2".to_owned()));
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn a_request_id_in_flight_is_refused_to_a_second_arrival() {
    let root = scratch("in-flight");
    let volume = Volume::claim(&root, AssuranceProfile::Development).expect("claimed");
    let (_, time) = guard();
    let trail = Arc::new(Trail::default());
    let engine = open(&volume, &trail, &time);
    let ledger = Ledger::default();
    let (entered, inside) = std::sync::mpsc::channel();
    let (release, wait) = std::sync::mpsc::channel::<()>();
    std::thread::scope(|scope| {
        let (engine, ledger) = (&engine, &ledger);
        let first = scope.spawn(move || {
            engine.run(begin(Some("r1"), "d1"), |applying| {
                entered.send(()).expect("the test listens");
                wait.recv().expect("the test releases");
                Ok::<_, Failure<String>>(ledger.apply(applying, "z1"))
            })
        });
        inside.recv().expect("the first is applying");
        let second = engine.run(
            begin(Some("r1"), "d1"),
            |_| -> Result<Applied<String>, Failure<String>> {
                panic!("a second arrival never applies")
            },
        );
        assert!(matches!(second, Err(MutationError::RequestIdReused(_))));
        release.send(()).expect("released");
        let first = first.join().expect("the first answers");
        assert_eq!(first.expect("applied"), Outcome::Applied("z1@1".to_owned()));
    });
    // Answered: the pair is free, and the retry learns the answer.
    assert_eq!(
        engine
            .run(
                begin(Some("r1"), "d1"),
                |_| -> Result<Applied<String>, Failure<String>> { panic!("replayed") }
            )
            .expect("replayed"),
        Outcome::Replayed("z1@1".to_owned())
    );
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn recovery_leaves_an_operation_of_this_process_alone() {
    let root = scratch("recover-running");
    let volume = Volume::claim(&root, AssuranceProfile::Development).expect("claimed");
    let (_, time) = guard();
    let trail = Arc::new(Trail::default());
    let engine = open(&volume, &trail, &time);
    let ledger = Ledger::default();
    let outcome = engine
        .run(begin(Some("r1"), "d1"), |applying| {
            // Between its intent and its commit, the domain not showing it yet.
            let recovered = engine.recover(&ledger).expect("recovers");
            assert_eq!(
                recovered,
                Recovered::default(),
                "nothing of a crash to resolve"
            );
            Ok::<_, Failure<String>>(ledger.apply(applying, "z1"))
        })
        .expect("applied");
    assert_eq!(outcome, Outcome::Applied("z1@1".to_owned()));
    assert_eq!(trail.phases(), vec!["intent", "applied"]);
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn an_outcome_record_refused_keeps_the_commit_and_a_retry_learns_it_once_written() {
    let root = scratch("outcome");
    let volume = Volume::claim(&root, AssuranceProfile::Development).expect("claimed");
    let (_, time) = guard();
    let trail = Arc::new(Trail::default());
    let ledger = Ledger::default();
    {
        let engine = open(&volume, &trail, &time);
        *trail.refuse_phase.lock().expect("lock") = Some("applied");
        let unrecorded = engine
            .run(begin(Some("r1"), "d1"), |applying| {
                Ok::<_, Failure<String>>(ledger.apply(applying, "z1"))
            })
            .expect_err("its outcome record failed");
        assert!(matches!(unrecorded, MutationError::Unrecorded(_)));
        assert_eq!(engine.pending(), 1);
        assert!(matches!(
            engine.run(
                begin(Some("r2"), "d2"),
                |_| -> Result<Applied<String>, Failure<String>> {
                    panic!("refused while a record waits")
                }
            ),
            Err(MutationError::AuditUnavailable(_))
        ));
        assert!(matches!(
            engine.run(
                begin(Some("r1"), "d1"),
                |_| -> Result<Applied<String>, Failure<String>> {
                    panic!("a retry never applies again")
                }
            ),
            Err(MutationError::Unrecorded(_))
        ));
    }
    // Across a fold at the next open, the commit and its pending record survive.
    let engine = open(&volume, &trail, &time);
    assert_eq!(engine.pending(), 1, "still waiting after the fold");
    *trail.refuse_phase.lock().expect("lock") = None;
    let replayed = engine
        .run(
            begin(Some("r1"), "d1"),
            |_| -> Result<Applied<String>, Failure<String>> {
                panic!("a retry never applies again")
            },
        )
        .expect("the committed answer, its record written now");
    assert_eq!(replayed, Outcome::Replayed("z1@1".to_owned()));
    assert_eq!(engine.pending(), 0);
    assert_eq!(trail.phases(), vec!["intent", "applied"]);
    assert_eq!(
        ledger.applied.lock().expect("lock").len(),
        1,
        "applied once"
    );
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn a_commit_that_fails_stops_the_journal_and_the_next_start_reconciles() {
    let root = scratch("commit-fails");
    let volume = Volume::claim(&root, AssuranceProfile::Development).expect("claimed");
    let (_, time) = guard();
    let trail = Arc::new(Trail::default());
    let ledger = Ledger::default();
    let journal = volume
        .host()
        .path()
        .join(crate::audit::DIRECTORY)
        .join(DIRECTORY);
    {
        let engine = open(&volume, &trail, &time);
        let health = Health::new();
        engine.observe(health.clone());
        let mut failing = None;
        let unrecorded = engine
            .run(begin(Some("r1"), "d1"), |applying| {
                let applied = ledger.apply(applying, "z1");
                failing = Some(permguard_core::fault::inject(
                    &journal,
                    permguard_core::fault::Fault::WriteFails,
                ));
                Ok::<_, Failure<String>>(applied)
            })
            .expect_err("the commit was not written");
        assert!(matches!(unrecorded, MutationError::Unrecorded(_)));
        drop(failing);
        // The journal takes nothing until the next start, and never says "nothing applied" of
        // the operation it left open.
        assert!(matches!(
            engine.run(
                begin(Some("r1"), "d1"),
                |_| -> Result<Applied<String>, Failure<String>> { panic!("never applied again") }
            ),
            Err(MutationError::Unrecorded(_))
        ));
        assert!(matches!(
            engine.run(
                begin(Some("r2"), "d2"),
                |_| -> Result<Applied<String>, Failure<String>> {
                    panic!("nothing new while the journal is stopped")
                }
            ),
            Err(MutationError::Unavailable(_))
        ));
        assert!(engine.pending() > 0);
        assert!(
            health
                .lifecycle()
                .report(permguard_core::lifecycle::HOST)
                .degraded
                .iter()
                .any(|degraded| degraded.capability == CAPABILITY)
        );
    }
    let engine = open(&volume, &trail, &time);
    let recovered = engine.recover(&ledger).expect("recovers");
    assert_eq!(recovered.reconciled.len(), 1);
    let learned = engine
        .run(
            begin(Some("r1"), "d1"),
            |_| -> Result<Applied<String>, Failure<String>> { panic!("never applied again") },
        )
        .expect("the retry learns the durable result");
    assert!(matches!(learned, Outcome::Reconciled { revision: 1, .. }));
    assert_eq!(trail.phases(), vec!["intent", "reconciled"]);
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn a_failed_journal_write_refuses_every_later_one_until_the_next_start() {
    let root = scratch("stopped");
    let volume = Volume::claim(&root, AssuranceProfile::Development).expect("claimed");
    let (_, time) = guard();
    let trail = Arc::new(Trail::default());
    let journal = volume
        .host()
        .path()
        .join(crate::audit::DIRECTORY)
        .join(DIRECTORY);
    let engine = open(&volume, &trail, &time);
    let entry = |byte: u8| {
        Entry::Intent(Intent {
            operation_id: OperationId::from_bytes([byte; 16]),
            at: 1,
            domain: "ledger".to_owned(),
            operation: "ledger.write".to_owned(),
            action: "host.grant.issued".to_owned(),
            initiator: Initiator::System("expiry".to_owned()),
            request: None,
            target: None,
        })
    };
    {
        let _failing =
            permguard_core::fault::inject(&journal, permguard_core::fault::Fault::WriteFails);
        engine.append(entry(1)).expect_err("the write fails");
    }
    // The file would take it now; the journal does not, since what the failure left is unknown.
    assert!(matches!(
        engine.append(entry(2)),
        Err(StorageError::Refused(_))
    ));
    drop(engine);
    let engine = open(&volume, &trail, &time);
    engine
        .append(entry(3))
        .expect("a new start takes writes again");
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn an_uncertain_domain_write_leaves_the_intent_for_the_next_start() {
    let root = scratch("indeterminate");
    let volume = Volume::claim(&root, AssuranceProfile::Development).expect("claimed");
    let (_, time) = guard();
    let trail = Arc::new(Trail::default());
    let ledger = Ledger::default();
    {
        let engine = open(&volume, &trail, &time);
        let uncertain = engine
            .run(begin(Some("r1"), "d1"), |applying| {
                // The write reached the domain, and its flush failed.
                ledger.apply(applying, "z1");
                Err::<Applied<String>, _>(Failure::Indeterminate("a flush failed".to_owned()))
            })
            .expect_err("uncertain");
        assert!(matches!(uncertain, MutationError::Indeterminate(_)));
        assert_eq!(
            engine.open_intents().len(),
            1,
            "left open, never marked failed"
        );
        assert!(matches!(
            engine.run(
                begin(Some("r1"), "d1"),
                |_| -> Result<Applied<String>, Failure<String>> { panic!("never applied again") }
            ),
            Err(MutationError::Unrecorded(_))
        ));
    }
    let engine = open(&volume, &trail, &time);
    let recovered = engine.recover(&ledger).expect("recovers");
    assert_eq!(recovered.reconciled.len(), 1, "the domain shows it");
    assert_eq!(trail.phases(), vec!["intent", "reconciled"]);
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn the_journal_folds_as_it_grows_and_keeps_what_a_retry_needs() {
    let root = scratch("fold");
    let volume = Volume::claim(&root, AssuranceProfile::Development).expect("claimed");
    let (_, time) = guard();
    let trail = Arc::new(Trail::default());
    let ledger = Ledger::default();
    let engine = open(&volume, &trail, &time).folding_after(4);
    for index in 0..5 {
        let request = format!("r{index}");
        engine
            .run(begin(Some(&request), "d"), |applying| {
                Ok::<_, Failure<String>>(ledger.apply(applying, &format!("z{index}")))
            })
            .expect("applied");
    }
    assert!(
        entries(&volume).len() < 15,
        "folded: three entries an operation, fewer left in the journal"
    );
    for index in 0..5 {
        let request = format!("r{index}");
        let answer = engine
            .run(
                begin(Some(&request), "d"),
                |_| -> Result<Applied<String>, Failure<String>> { panic!("replayed") },
            )
            .expect("replayed");
        assert_eq!(
            answer,
            Outcome::Replayed(format!("z{index}@{}", index + 1)),
            "the fold kept every answer inside the window"
        );
    }
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn a_refused_operation_is_failed_recorded_and_a_retry_applies_anew() {
    let root = scratch("refused");
    let volume = Volume::claim(&root, AssuranceProfile::Development).expect("claimed");
    let (_, time) = guard();
    let trail = Arc::new(Trail::default());
    let engine = open(&volume, &trail, &time);
    let ledger = Ledger::default();
    let refused = engine
        .run(
            begin(Some("r1"), "d1"),
            |_| -> Result<Applied<String>, Failure<String>> {
                Err(Failure::Refused("conflict".to_owned()))
            },
        )
        .expect_err("refused");
    assert!(matches!(refused, MutationError::Refused(reason) if reason == "conflict"));
    assert_eq!(trail.phases(), vec!["intent", "failed"]);
    assert!(matches!(entries(&volume)[1], Entry::Failed { .. }));
    let applied = engine
        .run(begin(Some("r1"), "d1"), |applying| {
            Ok::<_, Failure<String>>(ledger.apply(applying, "z1"))
        })
        .expect("applied anew");
    assert_eq!(applied, Outcome::Applied("z1@1".to_owned()));
    let records = trail.records.lock().expect("lock").clone();
    assert_ne!(records[0].1, records[2].1, "a new operation id");
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn recovery_commits_what_the_domain_shows_and_fails_what_it_does_not() {
    let root = scratch("recovery");
    let volume = Volume::claim(&root, AssuranceProfile::Development).expect("claimed");
    let (_, time) = guard();
    let trail = Arc::new(Trail::default());
    let ledger = Ledger::default();
    let (shown, lost) = {
        let engine = open(&volume, &trail, &time);
        // Two intents a crash left open: the domain applied the first and not the second.
        let intent = |request_id: &str| Intent {
            operation_id: OperationId::mint().expect("random"),
            at: 1,
            domain: "ledger".to_owned(),
            operation: "ledger.write".to_owned(),
            action: "host.grant.issued".to_owned(),
            initiator: Initiator::Principal("alice".to_owned()),
            request: Some(RequestKey {
                request_id: request_id.to_owned(),
                digest: "d".to_owned(),
            }),
            target: None,
        };
        let (shown, lost) = (intent("r1"), intent("r2"));
        engine
            .append(Entry::Intent(shown.clone()))
            .expect("appended");
        engine
            .append(Entry::Intent(lost.clone()))
            .expect("appended");
        ledger.apply(
            &Applying {
                operation_id: shown.operation_id,
                _engine: PhantomData,
            },
            "z1",
        );
        (shown.operation_id, lost.operation_id)
    };
    let engine = open(&volume, &trail, &time);
    assert_eq!(engine.open_intents().len(), 2, "visible until recovered");
    let recovered = engine.recover(&ledger).expect("recovers");
    assert_eq!(recovered.reconciled, vec![shown]);
    assert_eq!(recovered.failed, vec![lost]);
    assert!(engine.open_intents().is_empty());
    assert_eq!(engine.pending(), 0, "both outcomes recorded");
    let mut phases = trail.phases();
    phases.sort_unstable();
    assert_eq!(phases, vec!["failed", "reconciled"]);
    // A retry of the reconciled one learns its revision and target; of the failed one applies.
    let reconciled = engine
        .run(
            begin(Some("r1"), "d"),
            |_| -> Result<Applied<String>, Failure<String>> { panic!("never applied again") },
        )
        .expect("learned");
    assert_eq!(
        reconciled,
        Outcome::Reconciled {
            operation_id: shown,
            revision: 1,
            target: Some("z1".to_owned()),
        }
    );
    let fresh = engine
        .run(begin(Some("r2"), "d"), |applying| {
            Ok::<_, Failure<String>>(ledger.apply(applying, "z2"))
        })
        .expect("applied");
    assert_eq!(fresh, Outcome::Applied("z2@2".to_owned()));
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn an_audit_outage_refuses_new_mutations_degrades_the_host_and_heals_once_written() {
    let root = scratch("outage");
    let volume = Volume::claim(&root, AssuranceProfile::Development).expect("claimed");
    let (_, time) = guard();
    let trail = Arc::new(Trail::default());
    let engine = open(&volume, &trail, &time);
    let health = Health::new();
    engine.observe(health.clone());
    let ledger = Ledger::default();
    let degraded = |health: &Health| {
        health
            .lifecycle()
            .report(permguard_core::lifecycle::HOST)
            .degraded
            .iter()
            .any(|degraded| degraded.capability == CAPABILITY)
    };
    trail.refuse.store(true, Ordering::SeqCst);
    let refused = engine
        .run(
            begin(Some("r1"), "d1"),
            |_| -> Result<Applied<String>, Failure<String>> {
                panic!("nothing applies without its intent record")
            },
        )
        .expect_err("refused");
    assert!(matches!(refused, MutationError::AuditUnavailable(_)));
    assert_eq!(engine.pending(), 1, "the failure's record waits");
    assert!(degraded(&health));
    assert!(matches!(
        engine.run(
            begin(Some("r2"), "d2"),
            |_| -> Result<Applied<String>, Failure<String>> {
                panic!("refused while a record waits")
            }
        ),
        Err(MutationError::AuditUnavailable(_))
    ));
    trail.refuse.store(false, Ordering::SeqCst);
    engine
        .run(begin(Some("r2"), "d2"), |applying| {
            Ok::<_, Failure<String>>(ledger.apply(applying, "z1"))
        })
        .expect("applied once the trail is back");
    assert_eq!(engine.pending(), 0);
    assert!(!degraded(&health), "restored");
    assert_eq!(trail.phases(), vec!["failed", "intent", "applied"]);
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn an_operation_of_the_host_itself_has_no_request_and_is_never_replayed() {
    let root = scratch("system");
    let volume = Volume::claim(&root, AssuranceProfile::Development).expect("claimed");
    let (_, time) = guard();
    let trail = Arc::new(Trail::default());
    let engine = open(&volume, &trail, &time);
    let ledger = Ledger::default();
    let mut expiry = begin(None, "");
    expiry.initiator = Initiator::System("expiry".to_owned());
    for target in ["z1", "z2"] {
        let outcome = engine
            .run(expiry.clone(), |applying| {
                Ok::<_, Failure<String>>(ledger.apply(applying, target))
            })
            .expect("applied");
        assert!(matches!(outcome, Outcome::Applied(_)));
    }
    assert_eq!(ledger.applied.lock().expect("lock").len(), 2);
    drop(engine);
    // Committed, written and asked for by nobody: gone from the snapshot at the next open.
    let engine = open(&volume, &trail, &time);
    assert!(engine.state.lock().expect("lock").operations.is_empty());
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn a_torn_final_entry_is_cut_at_open() {
    let root = scratch("torn");
    let volume = Volume::claim(&root, AssuranceProfile::Development).expect("claimed");
    let (_, time) = guard();
    let trail = Arc::new(Trail::default());
    let path = {
        let engine = open(&volume, &trail, &time);
        let intent = Entry::Intent(Intent {
            operation_id: OperationId::mint().expect("random"),
            at: 1,
            domain: "ledger".to_owned(),
            operation: "ledger.write".to_owned(),
            action: "host.grant.issued".to_owned(),
            initiator: Initiator::System("expiry".to_owned()),
            request: None,
            target: None,
        });
        engine.append(intent.clone()).expect("appended");
        let path = engine.dir.child_path(JOURNAL);
        let mut bytes = std::fs::read(&path).expect("read");
        bytes.extend_from_slice(&intent.encode().expect("encodes")[..9]);
        std::fs::write(&path, bytes).expect("torn");
        path
    };
    let engine = open(&volume, &trail, &time);
    assert_eq!(engine.open_intents().len(), 1, "the whole entry is kept");
    assert!(std::fs::read(path).expect("read").is_empty(), "and folded");
    let _ = std::fs::remove_dir_all(root);
}
