// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! Applying a ledger's events to its histories in the order the journal made them durable.
//!
//! # Why a mutex was not enough
//!
//! Two things happen to a submitted occurrence, and they are not one step: the journal assigns it a
//! sequence and makes it durable, and then some history observes it. Between the two, the thread
//! carrying it is an ordinary thread — it can be descheduled, and the thread carrying the *next*
//! sequence can overtake it.
//!
//! A Dogwood history serialises its own observations behind a lock, so two threads never interleave
//! inside `is_authorized`. That makes the applications atomic; it does not make them *ordered*. The
//! lock is taken in whatever order the scheduler hands it out, so sequence 6 could be observed
//! before sequence 5 — and a temporal policy is a statement about order. A ledger that answered
//! "the read came before the login" once, under load, would answer it differently on replay, and
//! the journal — the authority — would disagree with the engine that decided from it.
//!
//! So the order is imposed here, from the sequence the journal already assigned, rather than hoped
//! for from the scheduler.
//!
//! # What is coordinated, and what is not
//!
//! One sequencer per `(zone, ledger)` — the scope the journal numbers. Not one global lock: two
//! ledgers have unrelated sequences and nothing to say to each other, and a lock spanning them
//! would make one ledger's slow evaluation another ledger's latency.
//!
//! Within a ledger the turn is held across the application, because releasing it earlier would
//! restore exactly the race it exists to remove. Histories inside one ledger are therefore applied
//! one at a time. That is the cost, and it is the right one to pay: the alternative is per-history
//! ordering derived from a per-ledger sequence, which cannot be done without knowing in advance
//! which history each sequence belongs to — and that is only known after the record is read.
//!
//! # Liveness
//!
//! A sequence that is journalled and then never applied — a submission that fails between the two,
//! which the error paths above this make possible — must not stop the ledger. The turn is released
//! by [`Turn`]'s drop, whatever happened, so the queue always advances. What that costs is a hole
//! in the applied history, and the submission path repairs it rather than carrying it: every path
//! that abandons a sequence marks that history for replay, so the next event in it is evaluated
//! against a run rebuilt from the journal instead of a prefix missing the abandoned sequence. The
//! record is durable either way, so a restart rebuilds it too — but a decision is never served
//! from the hole in the meantime.

use std::collections::BTreeMap;
use std::sync::{Arc, Condvar, Mutex};

/// One ledger's applied position.
struct State {
    /// The highest sequence whose turn has been given up, applied or not.
    through: u64,
    /// One application is in progress, including recovery of an older sequence.
    active: bool,
}

/// The turn-taking for one `(zone, ledger)`.
pub struct Sequencer {
    state: Mutex<State>,
    moved: Condvar,
}

impl Sequencer {
    /// A sequencer for a ledger whose journal has already made `applied_through` durable.
    ///
    /// Started from the journal rather than from zero: at open, the histories have been rebuilt
    /// from the records the journal holds, so everything up to its tail is applied. Starting at
    /// zero would make the first submission after a restart wait for sequences that were applied
    /// before it.
    pub fn starting_at(applied_through: u64) -> Self {
        Self {
            state: Mutex::new(State {
                through: applied_through,
                active: false,
            }),
            moved: Condvar::new(),
        }
    }

    /// Waits for every earlier sequence to have had its turn, then takes this one.
    ///
    /// The returned [`Turn`] must be held for the whole application and dropped after it.
    pub fn turn(self: &Arc<Self>, seq: u64) -> Turn {
        let mut state = match self.state.lock() {
            Ok(state) => state,
            Err(poisoned) => poisoned.into_inner(),
        };

        // A sequence at or below the mark had its turn already — a replay, or a journal that was
        // reopened behind this sequencer. Taking the turn anyway would wait for a predecessor that
        // is never coming.
        while state.active || state.through.saturating_add(1) < seq {
            state = match self.moved.wait(state) {
                Ok(state) => state,
                Err(poisoned) => poisoned.into_inner(),
            };
        }
        state.active = true;

        Turn {
            sequencer: Arc::clone(self),
            seq,
        }
    }

    /// The highest sequence this ledger has given a turn to.
    pub fn applied_through(&self) -> u64 {
        match self.state.lock() {
            Ok(state) => state.through,
            Err(poisoned) => poisoned.into_inner().through,
        }
    }

    fn release(&self, seq: u64) {
        {
            let mut state = match self.state.lock() {
                Ok(state) => state,
                Err(poisoned) => poisoned.into_inner(),
            };
            state.through = state.through.max(seq);
            state.active = false;
        }
        self.moved.notify_all();
    }
}

/// One sequence's turn to be applied. Released on drop, however the application ended.
pub struct Turn {
    sequencer: Arc<Sequencer>,
    seq: u64,
}

impl Turn {
    /// The sequence this turn is for.
    pub fn seq(&self) -> u64 {
        self.seq
    }
}

impl Drop for Turn {
    fn drop(&mut self) {
        self.sequencer.release(self.seq);
    }
}

/// Every ledger's sequencer, by `(zone, ledger)`.
#[derive(Default)]
pub struct Sequencers {
    held: Mutex<BTreeMap<(String, String), Arc<Sequencer>>>,
}

impl Sequencers {
    /// This ledger's sequencer, started from `applied_through` if it is the first ask.
    ///
    /// `applied_through` is only consulted when the sequencer is created: afterwards the sequencer
    /// is the authority, and a later reader's view of the journal — which may already include
    /// sequences whose turn has not come — must not move the mark.
    pub fn of(&self, zone: &str, ledger: &str, applied_through: u64) -> Arc<Sequencer> {
        let key = (zone.to_owned(), ledger.to_owned());
        let mut held = match self.held.lock() {
            Ok(held) => held,
            Err(poisoned) => poisoned.into_inner(),
        };

        Arc::clone(
            held.entry(key)
                .or_insert_with(|| Arc::new(Sequencer::starting_at(applied_through))),
        )
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    /// Turns are handed out in sequence order, whatever order they are asked for in.
    #[test]
    fn a_later_sequence_waits_for_the_one_before_it() {
        let sequencer = Arc::new(Sequencer::starting_at(0));
        let order = Arc::new(Mutex::new(Vec::new()));

        // Ask for the turns backwards, and start the later ones first, so the scheduler is given
        // every chance to run them out of order.
        let mut threads = Vec::new();
        for seq in (1..=8u64).rev() {
            let sequencer = Arc::clone(&sequencer);
            let order = Arc::clone(&order);
            threads.push(std::thread::spawn(move || {
                let turn = sequencer.turn(seq);
                order.lock().expect("not poisoned").push(turn.seq());
                // Held across the "application", the way the caller holds it.
                std::thread::yield_now();
                drop(turn);
            }));
            std::thread::yield_now();
        }
        for thread in threads {
            thread.join().expect("the thread finishes");
        }

        let order = order.lock().expect("not poisoned").clone();
        assert_eq!(
            order,
            (1..=8).collect::<Vec<u64>>(),
            "the journal's order is the order the histories saw"
        );
        assert_eq!(sequencer.applied_through(), 8);
    }

    /// A restart does not wait for sequences that were applied before it.
    #[test]
    fn a_sequencer_starts_from_what_the_journal_already_holds() {
        let sequencer = Arc::new(Sequencer::starting_at(41));
        let turn = sequencer.turn(42);
        assert_eq!(turn.seq(), 42);
        drop(turn);
        assert_eq!(sequencer.applied_through(), 42);
    }

    /// A submission that fails between the journal and the history must not stop the ledger.
    #[test]
    fn a_turn_dropped_without_being_applied_still_lets_the_ledger_move() {
        let sequencer = Arc::new(Sequencer::starting_at(0));
        // Sequence 1 is journalled and then abandoned — `history_scope` refused, say.
        drop(sequencer.turn(1));

        let waited = Arc::clone(&sequencer);
        let thread = std::thread::spawn(move || {
            let turn = waited.turn(2);
            turn.seq()
        });
        assert_eq!(
            thread.join().expect("the thread finishes"),
            2,
            "a hole in the applied history is repaired by the next submission, not waited for \
             forever"
        );
    }

    /// Recovery of an older durable sequence is still an application and excludes a new one.
    #[test]
    fn a_recovery_turn_serializes_with_the_live_tail() {
        let sequencer = Arc::new(Sequencer::starting_at(2));
        let recovery = sequencer.turn(1);
        let (sent, received) = std::sync::mpsc::channel();
        let live = Arc::clone(&sequencer);
        let thread = std::thread::spawn(move || {
            let turn = live.turn(3);
            sent.send(turn.seq()).expect("the result is observed");
            drop(turn);
        });
        assert!(
            received.try_recv().is_err(),
            "a live event must not enter while an older occurrence rebuilds the same ledger"
        );

        drop(recovery);
        assert_eq!(
            received
                .recv_timeout(std::time::Duration::from_secs(1))
                .expect("the live sequence continues after recovery"),
            3
        );
        thread.join().expect("the live application finishes");
    }

    /// One ledger's order is not another's.
    #[test]
    fn ledgers_do_not_wait_for_each_other() {
        let sequencers = Sequencers::default();
        let one = sequencers.of("zone", "ledger-a", 0);
        let two = sequencers.of("zone", "ledger-b", 0);

        let held = one.turn(1);
        // `ledger-b` is untouched by `ledger-a` holding its first turn.
        let other = two.turn(1);
        assert_eq!(other.seq(), 1);
        drop(other);
        drop(held);

        assert!(
            Arc::ptr_eq(&sequencers.of("zone", "ledger-a", 0), &one),
            "one sequencer per ledger, not one per call"
        );
    }
}
