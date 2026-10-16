// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::membership::Capabilities;
use crate::membership::record::{Capability, ContractRole};

/// WP-4.7: each of the six types has exactly one v1 contract, whose roles are the membership
/// model's, whose sides each have one server, and the Host's own contracts are the ones it
/// registers; only `zone.secrets` serves its bodies in this build.
#[test]
fn every_task_type_has_one_v1_contract_with_its_roles_and_server() {
    for task in TaskType::ALL {
        let found: Vec<&Contract> = CONTRACTS
            .iter()
            .filter(|contract| contract.task_type == task)
            .collect();
        assert_eq!(found.len(), 1, "{}", task.as_str());
        let contract = found[0];
        assert_eq!(contract.version, 1);
        assert_eq!(contract.provider, task.provider(), "{}", task.as_str());
        assert_eq!(contract.consumer, task.consumer(), "{}", task.as_str());
        assert_ne!(contract.provider, contract.consumer);
        assert_eq!(super::contract(task, 1), Some(contract));
        assert_eq!(super::contract(task, 2), None);
        // The Host serves both sides of a type or neither; a Plane serves only one side.
        match (contract.provided_by, contract.consumed_by) {
            (Server::Host, Server::Host) => assert!(host_served(task)),
            (Server::Plane(provider), Server::Plane(consumer)) => {
                assert_ne!(provider, consumer, "{}", task.as_str());
                assert!(!host_served(task));
            }
            other => panic!(
                "{}: one side the Host, the other a Plane: {other:?}",
                task.as_str()
            ),
        }
        assert_eq!(
            contract.served,
            matches!(
                task,
                TaskType::ZoneSecrets | TaskType::PolicyMirror | TaskType::AuditCheckpoints
            )
        );
    }
    let host: Vec<Capability> = Capabilities::host().list();
    let mut expected: Vec<Capability> = [TaskType::AuditCheckpoints, TaskType::ZoneSecrets]
        .into_iter()
        .flat_map(|task| {
            [ContractRole::Provider, ContractRole::Consumer].map(|role| Capability {
                task_type: task,
                version: 1,
                role,
            })
        })
        .collect();
    expected.sort();
    assert_eq!(
        host, expected,
        "the Host registers its own contracts, both sides"
    );
}
