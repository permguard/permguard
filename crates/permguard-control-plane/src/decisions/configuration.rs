// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! What this plane publishes about the decision log (WP-6.3b, owner decision of 2026-10-20).
//!
//! The third layer of the discovery chain for `permguard.api.decisions.native.v1`, shaped as the
//! event log's: the process names its planes, a plane names the interfaces it serves, and this
//! document says what the decision log offers here. Everything is derived from the constants the
//! routes are mounted from and the API family the offsets are bound to, so it cannot advertise a
//! path this plane does not answer. The common header (`version`, `component`, `state`, `stage`,
//! `limits`) is WP-7.4's, for every interface document.

use serde::{Deserialize, Serialize};

/// Where a control plane publishes what its decision log offers.
pub const CONFIGURATION_PATH: &str = "/.well-known/permguard-decisions-native-v1-configuration";

/// What this plane implements of `permguard.api.decisions.native.v1`, each implemented and
/// tested here: the event log's names, all of which hold for decisions too.
pub const CAPABILITIES: [&str; 6] = [
    // A batch is stored whole or not at all; a retry of one already stored is recognised.
    "atomic-batches",
    "idempotent-ingest",
    // A batch's signature is checked against a published producer key before it is stored.
    "attributed-records",
    // A read position is a MAC-authenticated opaque string bound to its scope.
    "authenticated-offsets",
    // A page states what it covered and whether its records are a contiguous chain.
    "read-coverage",
    // One tenant's records, by its ledger's concrete ids.
    "tenant-scoped-reads",
];

/// The parameters a read takes, as the contract's read table names them.
pub const READ_PARAMETERS: [&str; 9] = [
    "zone",
    "ledger",
    "pdp",
    "instance",
    "from",
    "until",
    "limit_records",
    "limit_bytes",
    "proof",
];

/// What this plane publishes about `permguard.api.decisions.native.v1`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Document {
    /// The contract and its version.
    pub interface: String,
    /// The common header (WP-7.4a): `version`, `component`, `state`, `stage` and `sunset`.
    #[serde(flatten)]
    pub header: permguard_core::stages::Header,
    /// This store's identifier.
    pub store: String,
    pub endpoints: Endpoints,
    pub capabilities: Vec<String>,
    pub offsets: Offsets,
    /// The parameters a read accepts.
    pub read_parameters: Vec<String>,
    /// What one page carries at most, whatever a reader asks for.
    pub limits: Limits,
}

/// Where batches are delivered, records read and signers answered.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Endpoints {
    /// Where a legacy producer delivers a batch.
    pub batches: String,
    /// One producer stream's records, named by `pdp` and `instance`.
    pub records: String,
    /// A tenant's records, a template with `{zone}` and `{ledger}`.
    pub tenant_records: String,
    /// One producer stream's signing-key spans.
    pub signers: String,
}

/// How a reader's position is spelled.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Offsets {
    /// The API family an offset issued here belongs to.
    pub api: String,
    /// `opaque`: this plane's to produce and to read, MAC-bound to its scope and bound.
    pub format: String,
    /// Whether an edited offset is accepted. It is not.
    pub editable: bool,
}

/// The ceilings a read is clamped to.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Limits {
    /// The most records one page carries.
    pub max_records: u64,
    /// The most bytes one page carries; one record larger than this is still returned alone.
    pub max_bytes: u64,
}

/// The document for a plane reached at `base`.
pub fn document(base: &str, store: &str, header: permguard_core::stages::Header) -> Document {
    let base = base.trim_end_matches('/');

    Document {
        interface: super::read::API.to_owned(),
        header,
        store: store.to_owned(),
        endpoints: Endpoints {
            // Built from the constants the router mounts, so the two cannot drift.
            batches: format!("{base}{}", super::http::BATCHES_PATH),
            records: format!("{base}{}", super::http::RECORDS_PATH),
            tenant_records: format!("{base}{}", super::http::TENANT_RECORDS_PATH),
            signers: format!("{base}{}", super::http::SIGNERS_PATH),
        },
        capabilities: CAPABILITIES.iter().map(|held| (*held).to_owned()).collect(),
        offsets: Offsets {
            api: super::read::API.to_owned(),
            format: "opaque".to_owned(),
            editable: false,
        },
        read_parameters: READ_PARAMETERS
            .iter()
            .map(|held| (*held).to_owned())
            .collect(),
        limits: Limits {
            max_records: permguard_stream::window::MAX_RECORDS as u64,
            max_bytes: permguard_stream::window::MAX_BYTES,
        },
    }
}

#[cfg(test)]
mod tests;
