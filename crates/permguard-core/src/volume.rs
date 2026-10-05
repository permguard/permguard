// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The Host's storage volume as configuration states it: the top-level `storage` section.
//!
//! | Key                                 | Meaning                                                                                    |
//! | ----------------------------------- | ------------------------------------------------------------------------------------------ |
//! | `storage.volume.storage_class`      | the storage class the volume comes from, declared by the operator                          |
//! | `storage.volume.driver`             | the driver or provider that attaches it, declared by the operator                          |
//! | `storage.qualified`                 | the qualified tuples: storage class, driver, filesystem, version and evidence              |
//! | `storage.compatibility_mode`        | the published compatibility mode for `production`; off by default                          |
//! | `storage.floors.free_bytes`         | the free bytes below which the volume is unsupported; 64 MiB by default                    |
//! | `storage.floors.free_inodes`        | the free inodes below which the volume is unsupported; 1,000 by default                    |
//! | `storage.floors.maintenance_bytes`  | within the floor, the bytes only GC and retention may use; 16 MiB, or the floor if smaller |
//! | `storage.floors.maintenance_inodes` | within the floor, the inodes only GC and retention may use; 100, or the floor if smaller   |
//! | `storage.quotas.host`               | the Host's bytes and inodes; absent is unlimited                                           |
//! | `storage.quotas.planes.<id>`        | one Plane's bytes and inodes, by Plane id; absent is unlimited                             |
//!
//! The filesystem and its version are never configured: the probe detects them. Configuration
//! states only what the process cannot see, and the qualified tuples it is compared with.

/// The free bytes below which a volume is unsupported, unless configuration says otherwise.
pub const DEFAULT_FREE_BYTES: u64 = 64 * 1024 * 1024;

/// The free inodes below which a volume is unsupported, unless configuration says otherwise.
pub const DEFAULT_FREE_INODES: u64 = 1_000;

/// Within the floor, the bytes only maintenance writers may use, unless configuration says
/// otherwise.
pub const DEFAULT_MAINTENANCE_BYTES: u64 = 16 * 1024 * 1024;

/// Within the floor, the inodes only maintenance writers may use, unless configuration says
/// otherwise.
pub const DEFAULT_MAINTENANCE_INODES: u64 = 100;

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
///
/// Ordinary writers never take free space below `free_bytes` and `free_inodes`, the emergency
/// floor. Maintenance writers — garbage collection, retention, the audit of their own action — may
/// use the floor down to `maintenance_bytes` and `maintenance_inodes`, which stay free whatever
/// happens, so a deletion can always write its anchor and its audit record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Floors {
    pub free_bytes: u64,
    pub free_inodes: u64,
    pub maintenance_bytes: u64,
    pub maintenance_inodes: u64,
}

impl Default for Floors {
    fn default() -> Self {
        Self {
            free_bytes: DEFAULT_FREE_BYTES,
            free_inodes: DEFAULT_FREE_INODES,
            maintenance_bytes: DEFAULT_MAINTENANCE_BYTES,
            maintenance_inodes: DEFAULT_MAINTENANCE_INODES,
        }
    }
}

/// A quota: the bytes and inodes a scope may hold; `None` is unlimited.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Limit {
    pub bytes: Option<u64>,
    pub inodes: Option<u64>,
}

/// The quotas configuration states: the Host's and each Plane's. Resource, stream and upload
/// session quotas come from the subsystem that owns them.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Quotas {
    pub host: Limit,
    pub planes: std::collections::BTreeMap<String, Limit>,
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
    pub quotas: Quotas,
}
