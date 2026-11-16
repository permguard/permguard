#![forbid(unsafe_code)]
// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The synchronization of the mirrors a Host follows (the crate boundaries refactoring, RD-12):
//! the round that discovers what the `policy.mirror` tasks list, pulls each ledger into its
//! verified mirror over the task's own session, and reaps what no task names any longer.
//!
//! | Module                     | What it is                                                              |
//! | -------------------------- | ----------------------------------------------------------------------- |
//! | [`source`]                 | where a mirror comes from: the task, its coordinator, its membership    |
//! | [`task`]                   | one ledger pulled over a task session and proven before it is switched  |
//! | [`round`]                  | one round over every task: discovery, pulls, contention, reaping        |
//! | [`progress`], [`hints`]    | what each mirror reports, and the hints a coordinator sends to hurry it |
//! | [`readiness`]              | whether the mirrors are current enough for the plane to say it is ready |
//! | [`measure`]                | what the loop counts about itself                                       |
//!
//! Client-neutral: who answers a pull is the session of a task the Host serves, and this package
//! opens no connection. What decides against a mirror is not here either: a round tells it that a
//! mirror advanced through [`Warm`], and hears back what warming it concluded.

pub mod hints;
pub mod measure;
pub mod progress;
pub mod readiness;
pub mod round;
pub mod source;
pub mod task;

// The layout, the verified state and the reap candidacy of a mirror are `permguard-mirror`'s.
pub use permguard_mirror::{layout, state, tombstone};

/// What warming one mirror concluded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Warmed {
    /// Compiled and held; `compiled` counts what this call had to build.
    Ready { compiled: usize },
    /// Nothing to serve yet: a ledger nobody has applied to.
    Empty,
    /// This engine may not serve it, and the block file says so.
    Blocked(String),
    /// The mirror is unreadable — a missing or corrupt object.
    Damaged(String),
}

impl Warmed {
    /// One word, for the log line and the metric label.
    pub fn label(&self) -> &'static str {
        match self {
            Self::Ready { .. } => "ready",
            Self::Empty => "empty",
            Self::Blocked(_) => "blocked",
            Self::Damaged(_) => "damaged",
        }
    }
}

/// What a round tells that a mirror advanced: whoever decides against it, which reads it, says
/// whether it may serve it, and compiles it if it may. Off the decision path, and blocking: a
/// round calls it on the blocking pool.
pub trait Warm: Send + Sync {
    fn warm(&self, mirror: &permguard_mirror::held::Mirror) -> Warmed;
}
