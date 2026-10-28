// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The vector frontier a temporal decision observed (WP-6.4a, owner decision of 2026-10-21).
//!
//! There is no global sequence across Hosts: imported history is a set of origin streams, and a
//! decision over it cites, per origin and run, how far it held, what it still retained and where
//! it has holes. One shape for the answer's `history` and for the decision record's `event`
//! reference, so an auditor reads in the record exactly what the caller was told.

use serde::{Deserialize, Serialize};

/// The time a temporal runtime's windows range over: the source's claimed event time.
pub const TIME_OCCURRED_AT: &str = "occurred_at";

/// One imported run of one origin, as a decision held it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FrontierRun {
    /// The origin Host, in hex.
    pub origin: String,
    /// Its run, in hex.
    pub run: String,
    /// The last sequence held, contiguously.
    pub covered_through: u64,
    /// The oldest sequence still retained.
    pub low_watermark: u64,
    /// The holes recorded in the run.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub gaps: Vec<FrontierGap>,
}

/// One recorded hole in a run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FrontierGap {
    /// The first sequence missing.
    pub from: u64,
    /// The last sequence missing, when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub through: Option<u64>,
}
