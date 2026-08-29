// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! Where a read stopped, in a form that is honest about what it covers.
//!
//! # One producer, one number; several producers, no number
//!
//! For a single producer stream a watermark is one exclusive sequence: everything below it was
//! observed, everything at or above it was not. That is a number, and it means something.
//!
//! For a tenant's view of a ledger, several producers contribute and there is no truthful total
//! order across them. A single number there would be a fabrication — it would have to pretend that
//! producer A's sequence 40 comes before producer B's 41, which nothing establishes. So the
//! frontier is the covered position of *every* contributing producer, and a client echoes it
//! rather than comparing it.
//!
//! A producer that appears after a finite snapshot began is outside that snapshot, and that is the
//! correct answer rather than a gap: the export captured a frontier, and a producer absent from it
//! contributes nothing to it.

use std::collections::BTreeMap;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use serde::{Deserialize, Serialize};

/// How far a read observed, across whatever contributes to its scope.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Frontier {
    /// The frontier format, so a later shape can be told from this one rather than guessed at.
    pub v: u32,
    /// The exclusive covered position of each contributing producer, by stream key.
    ///
    /// A `BTreeMap`, so two frontiers over the same producers encode identically and a client that
    /// stores one gets it back unchanged.
    pub covered: BTreeMap<String, u64>,
}

/// The frontier format this build writes.
pub const VERSION: u32 = 1;

impl Frontier {
    /// The frontier of a single producer stream at `sequence`, exclusive.
    pub fn of(stream: &str, sequence: u64) -> Self {
        let mut covered = BTreeMap::new();
        covered.insert(stream.to_owned(), sequence);

        Self {
            v: VERSION,
            covered,
        }
    }

    /// An empty frontier: nothing observed, which is where a fresh reader stands.
    pub fn empty() -> Self {
        Self {
            v: VERSION,
            covered: BTreeMap::new(),
        }
    }

    /// Records that this producer was observed up to `sequence`, exclusive.
    pub fn cover(&mut self, stream: &str, sequence: u64) {
        let held = self.covered.entry(stream.to_owned()).or_default();
        // Monotonic: a frontier only ever moves forward, so a page that read less of one producer
        // than a previous page did does not walk it back.
        *held = (*held).max(sequence);
    }

    /// How far this frontier covers one producer, exclusive.
    pub fn covered_through(&self, stream: &str) -> u64 {
        self.covered.get(stream).copied().unwrap_or_default()
    }

    /// Whether this frontier covers everything the other one does.
    ///
    /// What "the export is finished" means: every producer the snapshot bounded has been read to
    /// the position the snapshot recorded. A producer the bound does not name is outside it, and
    /// contributes nothing either way.
    pub fn reached(&self, bound: &Frontier) -> bool {
        bound
            .covered
            .iter()
            .all(|(stream, sequence)| self.covered_through(stream) >= *sequence)
    }

    /// The opaque token a client echoes.
    ///
    /// Opaque because a client must not compare frontiers numerically: for a merged view there is
    /// no number to compare, and a client that learned to read the single-producer case would
    /// silently do the wrong thing the day a second producer appeared. It echoes what it was
    /// given, and the server does the comparing.
    pub fn encode(&self) -> String {
        let body = serde_json::to_vec(self).unwrap_or_default();

        B64.encode(body)
    }

    /// Reads a token back, or `None` for something this build did not issue.
    pub fn decode(token: &str) -> Option<Self> {
        let bytes = B64.decode(token).ok()?;
        let frontier: Self = serde_json::from_slice(&bytes).ok()?;
        if frontier.v != VERSION {
            return None;
        }

        Some(frontier)
    }

    /// Whether this frontier names exactly one producer, and which.
    ///
    /// A single-producer read may present its frontier as the number it is; a merged view may not.
    pub fn single(&self) -> Option<(&str, u64)> {
        match self.covered.len() {
            1 => self
                .covered
                .iter()
                .next()
                .map(|(stream, sequence)| (stream.as_str(), *sequence)),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_frontier_only_moves_forward() {
        let mut frontier = Frontier::of("a", 10);
        frontier.cover("a", 4);

        assert_eq!(
            frontier.covered_through("a"),
            10,
            "a page that read less does not walk it back"
        );
        frontier.cover("a", 12);
        assert_eq!(frontier.covered_through("a"), 12);
    }

    /// An export finishes when every producer its snapshot bounded has been read to that bound.
    #[test]
    fn an_export_finishes_when_it_reaches_the_bound_it_captured() {
        let mut bound = Frontier::of("a", 10);
        bound.cover("b", 3);

        let mut read = Frontier::of("a", 10);
        assert!(!read.reached(&bound), "`b` has not been read yet");
        read.cover("b", 3);
        assert!(read.reached(&bound));
    }

    /// A producer that appears after the snapshot is outside it, rather than making it endless.
    #[test]
    fn a_producer_the_snapshot_never_saw_is_outside_it() {
        let bound = Frontier::of("a", 10);
        let mut read = Frontier::of("a", 10);
        read.cover("newcomer", 99);

        assert!(
            read.reached(&bound),
            "the snapshot bounded `a`, and `a` is done"
        );
    }

    /// A client echoes the token; it does not read it.
    #[test]
    fn a_frontier_round_trips_through_its_opaque_token() {
        let mut frontier = Frontier::of("a", 10);
        frontier.cover("b", 3);

        assert_eq!(Frontier::decode(&frontier.encode()), Some(frontier));
        assert_eq!(Frontier::decode("not-a-frontier!!"), None);
    }

    #[test]
    fn a_merged_view_has_no_single_number_and_says_so() {
        let mut merged = Frontier::of("a", 1);
        merged.cover("b", 2);

        assert_eq!(Frontier::of("a", 7).single(), Some(("a", 7)));
        assert_eq!(
            merged.single(),
            None,
            "there is no truthful total order across producers"
        );
    }
}
