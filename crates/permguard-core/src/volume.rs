// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The Host's storage volume as configuration states it: the top-level `storage` section.
//!
//! | Key                            | Meaning                                                                       |
//! | ------------------------------ | ----------------------------------------------------------------------------- |
//! | `storage.volume.storage_class` | the storage class the volume comes from, declared by the operator             |
//! | `storage.volume.driver`        | the driver or provider that attaches it, declared by the operator             |
//! | `storage.qualified`            | the qualified tuples: storage class, driver, filesystem, version and evidence |
//! | `storage.compatibility_mode`   | the published compatibility mode for `production`; off by default             |
//! | `storage.floors.free_bytes`    | the free bytes below which the volume is unsupported; 64 MiB by default       |
//! | `storage.floors.free_inodes`   | the free inodes below which the volume is unsupported; 1,000 by default       |
//!
//! The filesystem and its version are never configured: the probe detects them. Configuration
//! states only what the process cannot see, and the qualified tuples it is compared with.

/// The free bytes below which a volume is unsupported, unless configuration says otherwise.
pub const DEFAULT_FREE_BYTES: u64 = 64 * 1024 * 1024;

/// The free inodes below which a volume is unsupported, unless configuration says otherwise.
pub const DEFAULT_FREE_INODES: u64 = 1_000;

/// A storage class, driver, filesystem and version: what a qualification is about.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Tuple {
    pub storage_class: String,
    pub driver: String,
    pub filesystem: String,
    pub version: String,
}

/// A tuple whose crash and forced-takeover tests are recorded as deployment evidence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QualifiedTuple {
    pub tuple: Tuple,
    /// Where the evidence is recorded: a document, a ticket, a report.
    pub evidence: String,
}

/// The safety floors of the volume.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Floors {
    pub free_bytes: u64,
    pub free_inodes: u64,
}

impl Default for Floors {
    fn default() -> Self {
        Self {
            free_bytes: DEFAULT_FREE_BYTES,
            free_inodes: DEFAULT_FREE_INODES,
        }
    }
}

/// The `storage` section, read and validated.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct VolumeConfig {
    /// The storage class the operator declares, when it does.
    pub storage_class: Option<String>,
    /// The driver the operator declares, when it does.
    pub driver: Option<String>,
    pub qualified: Vec<QualifiedTuple>,
    /// Published by discovery and `host status` whenever it is on.
    pub compatibility_mode: bool,
    pub floors: Floors,
}
