// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The task type contracts, version 1 (WP-4.7; owner decision of 2026-10-12).
//!
//! | Task type           | Provider    | Consumer    | Provided by   | Consumed by   | Bodies               |
//! | ------------------- | ----------- | ----------- | ------------- | ------------- | -------------------- |
//! | `policy.mirror`     | coordinator | member      | Control Plane | Data Plane    | WP-7.x               |
//! | `decisions.ship`    | member      | coordinator | Data Plane    | Control Plane | WP-5.x               |
//! | `events.ship`       | member      | coordinator | Data Plane    | Control Plane | WP-5.x               |
//! | `events.import`     | coordinator | member      | Control Plane | Host          | [`super::import`]    |
//! | `audit.checkpoints` | member      | coordinator | Host          | Host          | the audit export     |
//! | `zone.secrets`      | coordinator | member      | Host          | Host          | [`super::zone`]      |
//!
//! Each side of a type has exactly one server: one Plane, or the Host, and no Plane may claim a
//! side the Host serves (`composition::Host::register` refuses it). `events.import` is served by
//! the Control Plane and consumed by the member's Host, which ingests the origins' batches into its
//! own consumer (owner decision of 2026-10-19). A contract whose bodies have not arrived answers
//! `not_served_yet` at the coordinator.

use super::record::{Role, TaskType};

/// What serves one side of a contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Server {
    /// The Host itself, whatever Planes it composes.
    Host,
    /// The Plane of this name, as its declaration registers it.
    Plane(&'static str),
}

/// One versioned task contract: its roles, the server of each side and where its messages are
/// defined.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Contract {
    pub task_type: TaskType,
    pub version: u64,
    pub provider: Role,
    pub consumer: Role,
    pub provided_by: Server,
    pub consumed_by: Server,
    /// The document or module defining its message bodies.
    pub messages: &'static str,
    /// Whether this build serves its bodies; one that does not answers `not_served_yet`.
    pub served: bool,
}

/// The contracts this build speaks: one per task type, version 1.
pub const CONTRACTS: [Contract; 6] = [
    Contract {
        task_type: TaskType::PolicyMirror,
        version: 1,
        provider: Role::Coordinator,
        consumer: Role::Member,
        provided_by: Server::Plane("control"),
        consumed_by: Server::Plane("data"),
        messages: "6-contracts/6-contract-ledger-notp.md: the NOTP pull messages and WatchRefs",
        served: true,
    },
    Contract {
        task_type: TaskType::DecisionsShip,
        version: 1,
        provider: Role::Member,
        consumer: Role::Coordinator,
        provided_by: Server::Plane("data"),
        consumed_by: Server::Plane("control"),
        messages: "6-contracts/3-contract-evidence-decisions.md: decision evidence batches",
        served: false,
    },
    Contract {
        task_type: TaskType::EventsShip,
        version: 1,
        provider: Role::Member,
        consumer: Role::Coordinator,
        provided_by: Server::Plane("data"),
        consumed_by: Server::Plane("control"),
        messages: "6-contracts/4-contract-evidence-events.md: event evidence batches",
        served: false,
    },
    Contract {
        task_type: TaskType::EventsImport,
        version: 1,
        provider: Role::Coordinator,
        consumer: Role::Member,
        provided_by: Server::Plane("control"),
        consumed_by: Server::Host,
        messages: "permguard_host::membership::import: origins with their checkpoint, and batches as the origins shipped them",
        served: true,
    },
    Contract {
        task_type: TaskType::AuditCheckpoints,
        version: 1,
        provider: Role::Member,
        consumer: Role::Coordinator,
        provided_by: Server::Host,
        consumed_by: Server::Host,
        messages: "permguard_host::membership::egress: checkpoint shipment and acknowledgement; a fork of the trail refused as `fork`",
        served: true,
    },
    Contract {
        task_type: TaskType::ZoneSecrets,
        version: super::zone::VERSION,
        provider: Role::Coordinator,
        consumer: Role::Member,
        provided_by: Server::Host,
        consumed_by: Server::Host,
        messages: "permguard_host::membership::zone: request, delivery, confirmation, receipt",
        served: true,
    },
];

/// The contract of `task` at `version`, when this build speaks it.
pub fn contract(task: TaskType, version: u64) -> Option<&'static Contract> {
    CONTRACTS
        .iter()
        .find(|contract| contract.task_type == task && contract.version == version)
}

/// Whether the Host serves the `role` side of `task`, so that no Plane may claim it.
pub fn host_side(task: TaskType, role: super::record::ContractRole) -> bool {
    CONTRACTS.iter().any(|contract| {
        contract.task_type == task
            && match role {
                super::record::ContractRole::Provider => contract.provided_by == Server::Host,
                super::record::ContractRole::Consumer => contract.consumed_by == Server::Host,
            }
    })
}

/// Whether the Host serves both sides of `task`.
pub fn host_served(task: TaskType) -> bool {
    CONTRACTS.iter().any(|contract| {
        contract.task_type == task
            && contract.provided_by == Server::Host
            && contract.consumed_by == Server::Host
    })
}

#[cfg(test)]
mod tests;
