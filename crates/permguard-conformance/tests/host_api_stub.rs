// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The Host API proto declares the six services of the Host API contract, each a server trait, and
//! a message gets its fields only when the package that serves its operation defines the shape.

use std::collections::BTreeSet;

use permguard_conformance::contracts::host_v1;

/// Naming a generated server proves the service exists; a missing or renamed one fails to compile.
fn served<T>() -> &'static str {
    std::any::type_name::<T>()
}

#[test]
fn test_the_host_api_declares_the_six_services_of_the_contract() {
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

/// The messages whose operations the Host listener serves (WP-2.5): the only ones with fields.
/// A package that serves another operation adds its messages here with its OpenAPI mapping.
const SHAPED: &[&str] = &[
    "ListGrantsRequest",
    "ListGrantsResponse",
    "Grant",
    "Receipt",
    "AuditReference",
    "CreateGrantRequest",
    "CreateGrantResponse",
    "PlanGrantRevokeRequest",
    "PlanGrantRevokeResponse",
    "RunGrantRevokeRequest",
    "RunGrantRevokeResponse",
    "ListKeyRingsResponse",
    "KeyRingSummary",
    "GetKeyRingRequest",
    "GetKeyRingResponse",
    "Jwk",
    "GetStatusResponse",
    "HostDegraded",
    "HostComponent",
    "Assurance",
    "GetEffectiveConfigResponse",
    "Setting",
    "ListConfigRevisionsResponse",
    "ConfigRevision",
];

/// Every message outside [`SHAPED`] is empty: no field number is assigned ahead of the contract.
#[test]
fn test_no_unserved_host_api_message_assigns_a_field_number_yet() {
    let source = std::fs::read_to_string(
        permguard_conformance::contracts::root().join("proto/permguard/host/v1/host.proto"),
    )
    .expect("the proto is checked in");
    let shaped: BTreeSet<&str> = SHAPED.iter().copied().collect();
    let mut current: Option<String> = None;
    let mut offences = Vec::new();
    let mut seen = BTreeSet::new();
    for line in source.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("message ") {
            let name = rest.split([' ', '{']).next().unwrap_or_default().to_owned();
            if trimmed.ends_with("{}") {
                current = None;
            } else {
                current = Some(name.clone());
            }
            seen.insert(name);
            continue;
        }
        if trimmed == "}" {
            current = None;
            continue;
        }
        let field = !trimmed.starts_with("//")
            && trimmed.ends_with(';')
            && trimmed
                .rsplit_once(" = ")
                .is_some_and(|(_, number)| number.trim_end_matches(';').parse::<u32>().is_ok());
        if field
            && let Some(message) = &current
            && !shaped.contains(message.as_str())
        {
            offences.push(format!("{message}: `{trimmed}`"));
        }
    }
    assert!(
        offences.is_empty(),
        "field numbers assigned to messages no package serves: {offences:#?}"
    );
    for name in SHAPED {
        assert!(
            seen.contains(*name),
            "`{name}` is listed as shaped and is no message"
        );
    }
}
