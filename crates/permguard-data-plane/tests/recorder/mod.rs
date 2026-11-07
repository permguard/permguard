// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! What these tests record decisions with, in place of the Host's stream: every record a line of
//! JSON in one file of a directory, read back the way the tests read a spool. The body is built by
//! the plane's own [`decision_body`], so what a test reads is what the Host would be handed.

#![allow(dead_code)]

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use permguard_data_plane::decisions::record::{Epoch, decision_body};
use permguard_data_plane::decisions::{Decided, DecisionRecorder, Written};
use permguard_decisions::Commitment;
use permguard_decisions::spool::Bounds;

/// Whether a decision that cannot be recorded is refused (`Closed`) or answered (`Open`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WhenFull {
    Open,
    Closed,
}

/// A recorder over `directory`.
pub struct TestRecorder {
    file: PathBuf,
    when_full: WhenFull,
    /// No room at all: every record fails, as a full log does.
    full: bool,
    epoch: Epoch,
    commitment: Commitment,
    written: Mutex<u64>,
}

impl TestRecorder {
    /// A recorder writing under `directory`; `bounds.bytes` of 1 leaves it no room.
    pub fn open(
        directory: impl AsRef<Path>,
        when_full: WhenFull,
        bounds: Bounds,
    ) -> std::io::Result<Self> {
        let directory = directory.as_ref();
        std::fs::create_dir_all(directory)?;
        Ok(Self {
            file: directory.join("seg-00000000000000000001.jsonl"),
            when_full,
            full: bounds.bytes <= 1,
            epoch: Epoch {
                version: "0.1.0".to_owned(),
                build: None,
                engines: std::collections::BTreeMap::new(),
                sampling: "1.0".to_owned(),
            },
            commitment: Commitment::new(*b"a-key-of-at-least-32-bytes-long!!", "v1"),
            written: Mutex::new(0),
        })
    }

    /// A recorder whose every write fails, as a disk refusing the next segment does.
    pub fn failing(directory: impl AsRef<Path>, when_full: WhenFull) -> std::io::Result<Self> {
        let mut recorder = Self::open(
            directory,
            when_full,
            Bounds {
                bytes: 1,
                age: std::time::Duration::from_secs(3600),
                segment_bytes: 1,
            },
        )?;
        recorder.full = true;
        Ok(recorder)
    }
}

impl DecisionRecorder for TestRecorder {
    fn record(&self, decided: &Decided<'_>) -> Result<Written, String> {
        if self.full {
            return Err("the decision log has no room".to_owned());
        }
        let body = decision_body(&self.epoch, &self.commitment, decided);
        let line = serde_json::to_string(&body).map_err(|error| error.to_string())?;
        let mut written = self.written.lock().map_err(|_| "poisoned".to_owned())?;
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.file)
            .map_err(|error| error.to_string())?;
        writeln!(file, "{line}").map_err(|error| error.to_string())?;
        *written += 1;
        Ok(Written::Recorded { seq: *written })
    }

    fn record_located(
        &self,
        decided: &Decided<'_>,
    ) -> Result<(Written, Option<permguard_languages::attestation::Position>), String> {
        self.record(decided).map(|written| (written, None))
    }

    fn refuses_unrecorded(&self) -> bool {
        self.when_full == WhenFull::Closed
    }
}
