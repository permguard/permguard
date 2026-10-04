// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The Host API stub declares the six services of the Host API contract, each a server trait.

use permguard_conformance::contracts::host_v1;

/// Naming a generated server proves the service exists; a missing or renamed one fails to compile.
fn served<T>() -> &'static str {
    std::any::type_name::<T>()
}

#[test]
fn test_the_host_api_stub_declares_the_six_services_of_the_contract() {
    let services = [
        served::<host_v1::identity_service_server::IdentityServiceServer<()>>(),
        served::<host_v1::membership_service_server::MembershipServiceServer<()>>(),
        served::<host_v1::grant_service_server::GrantServiceServer<()>>(),
        served::<host_v1::key_service_server::KeyServiceServer<()>>(),
        served::<host_v1::evidence_service_server::EvidenceServiceServer<()>>(),
        served::<host_v1::operations_service_server::OperationsServiceServer<()>>(),
    ];
    assert_eq!(services.len(), 6);
}

/// Every message is empty until the package implementing its operation defines the shape: no
/// field number is assigned ahead of the contract.
#[test]
fn test_no_host_api_message_assigns_a_field_number_yet() {
    let source = std::fs::read_to_string(
        permguard_conformance::contracts::root().join("proto/permguard/host/v1/host.proto"),
    )
    .expect("the stub is checked in");
    let fields: Vec<&str> = source
        .lines()
        .filter(|line| {
            let line = line.trim();
            !line.starts_with("//")
                && line.ends_with(';')
                && line
                    .rsplit_once(" = ")
                    .is_some_and(|(_, number)| number.trim_end_matches(';').parse::<u32>().is_ok())
        })
        .collect();
    assert!(fields.is_empty(), "field numbers assigned: {fields:#?}");
}
