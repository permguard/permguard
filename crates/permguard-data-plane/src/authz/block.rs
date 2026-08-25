// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The memory of a refusal: one file beside a mirror, naming the commit this
//! engine could not serve and why.
//!
//! # The problem it solves
//!
//! A ledger whose manifest this engine is outside the range of — a language
//! version raised, an engine range narrowed, a schema no longer satisfied —
//! cannot be served. That is settled and it will stay settled until the ledger
//! *changes*. Rediscovering it every synchronization round would mean reading
//! every object and compiling every policy on a loop, to reach the same
//! answer: expensive, and noisy in a way that trains an operator to ignore the
//! log.
//!
//! So the refusal is written down:
//!
//! ```text
//! <mirror>/BLOCKED   { commit, reason, at }
//! ```
//!
//! # How it clears itself
//!
//! There is nothing to configure and no timer to tune. The rule is one line:
//!
//! > if the block names the commit that is now the head, skip; otherwise try
//! > again.
//!
//! A synchronization that brings a *new* commit therefore retries on its own —
//! which is exactly the moment something might have changed. A ledger that
//! stays put stays blocked, for free. And because the block is a file on the
//! volume, a plane that restarts does not forget what it learned.
//!
//! # What it is not
//!
//! It is not a deny cache. A blocked ledger answers **unavailable**, never
//! `decision: false`: a PEP must be able to tell "no" from "this PDP cannot
//! serve this ledger", because the two call for different behaviour on its
//! side.

use std::path::Path;

use serde::{Deserialize, Serialize};

/// The file, inside the mirror.
pub const BLOCK_FILE: &str = "BLOCKED";

/// What was refused, and why.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Block {
    /// The commit that could not be served. The whole mechanism turns on this.
    pub commit: String,
    /// The sentence an operator needs — the load gate's own words.
    pub reason: String,
    /// When it was decided, as seconds since the epoch, for the report.
    pub at: u64,
}

/// Writes the block, replacing any earlier one.
///
/// Best-effort on purpose: a volume that cannot be written is a problem, but
/// it is not a reason to fail a decision path that is already refusing.
pub fn write(mirror: &Path, commit: &str, reason: &str) {
    let block = Block {
        commit: commit.to_owned(),
        reason: reason.to_owned(),
        at: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|since| since.as_secs())
            .unwrap_or_default(),
    };
    let Ok(bytes) = serde_json::to_vec_pretty(&block) else {
        return;
    };
    let _ = std::fs::write(mirror.join(BLOCK_FILE), bytes);
}

/// Reads the block, when there is one.
pub fn read(mirror: &Path) -> Option<Block> {
    let bytes = std::fs::read(mirror.join(BLOCK_FILE)).ok()?;

    serde_json::from_slice(&bytes).ok()
}

/// Whether this commit is the one that was refused.
///
/// The only question anybody asks: a block that names another commit is a
/// block about the past, and the past is not what is being served.
pub fn blocks(mirror: &Path, commit: &str) -> Option<Block> {
    read(mirror).filter(|block| block.commit == commit)
}

/// Forgets the block. Called when a commit is served successfully, so a ledger
/// that was fixed does not carry a stale accusation on its volume.
pub fn clear(mirror: &Path) {
    let _ = std::fs::remove_file(mirror.join(BLOCK_FILE));
}

/// Clears a block only if one is there — a filesystem call skipped on the
/// path every request takes, which is the common one.
pub fn clear_if_present(mirror: &Path) {
    if mirror.join(BLOCK_FILE).exists() {
        clear(mirror);
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;
    use std::path::PathBuf;

    fn scratch(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "pg-authz-block-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("the scratch directory is created");
        dir
    }

    #[test]
    fn a_block_stops_the_commit_it_names_and_nothing_else() {
        let mirror = scratch("names");
        write(
            &mirror,
            "sha256:aaa",
            "engine 9 is outside `>=0.1.0 <0.2.0`",
        );

        let block = blocks(&mirror, "sha256:aaa").expect("this commit is blocked");
        assert!(block.reason.contains("engine 9"));
        assert!(
            blocks(&mirror, "sha256:bbb").is_none(),
            "a new commit is a new chance"
        );
    }

    #[test]
    fn a_mirror_with_no_block_blocks_nothing() {
        let mirror = scratch("clean");

        assert!(read(&mirror).is_none());
        assert!(blocks(&mirror, "sha256:aaa").is_none());
    }

    #[test]
    fn clearing_it_forgets_it() {
        let mirror = scratch("clear");
        write(&mirror, "sha256:aaa", "whatever it was");
        assert!(read(&mirror).is_some());

        clear(&mirror);
        assert!(read(&mirror).is_none());
        // Clearing what is not there is not an error: a ledger that was never
        // blocked is the common case.
        clear(&mirror);
    }

    #[test]
    fn a_block_that_is_not_json_is_no_block_at_all() {
        let mirror = scratch("garbage");
        std::fs::write(mirror.join(BLOCK_FILE), b"not json").expect("the file is written");

        assert!(
            read(&mirror).is_none(),
            "unreadable means unknown, and unknown means try again"
        );
    }
}
