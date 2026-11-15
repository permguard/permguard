// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! Owner decision of 2026-11-15: the members a page names are the same over REST and over gRPC,
//! over the event reads' own fixture.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::sync::Arc;

use crate::testing::events::*;
use permguard_core::encoding::hex;
use serde_json::json;

struct NamesOne;

impl crate::members::NamesMembers for NamesOne {
    fn member_named(&self, host_id: &[u8; 16]) -> Option<crate::members::MemberName> {
        (*host_id == [1; 16]).then(|| crate::members::MemberName {
            member_id: "01a1b9de-8738-736e-9fff-609509b3fcbb".to_owned(),
            name: "lab-a".to_owned(),
        })
    }
}

/// Owner decision of 2026-11-15: the members a page names are the same over REST and over gRPC,
/// beside the records, and a producer no membership names is left out of both.
#[tokio::test]
async fn the_members_a_page_names_are_the_same_over_rest_and_grpc() {
    use crate::v1::event_log_server::EventLog;
    use http_body_util::BodyExt as _;
    use tower::ServiceExt as _;

    let fixture = Fixture::new("members");
    let facade = permguard_control_plane::events::facade::EventFacade {
        members: Some(Arc::new(NamesOne)),
        ..facade(&fixture)
    };
    let actor = Arc::new(permguard_core::authz::Actor::Anonymous);

    let router =
        crate::events::http::routes(facade.clone()).layer(axum::Extension(Arc::clone(&actor)));
    let response = router
        .oneshot(
            axum::http::Request::builder()
                .uri(format!(
                    "/events/v1alpha1/zones/{ZONE}/ledgers/{LEDGER}/records"
                ))
                .body(axum::body::Body::empty())
                .expect("a request"),
        )
        .await
        .expect("answered");
    assert_eq!(response.status(), axum::http::StatusCode::OK);
    let bytes = response
        .into_body()
        .collect()
        .await
        .expect("the body reads")
        .to_bytes();
    let rest: serde_json::Value = serde_json::from_slice(&bytes).expect("JSON");
    let named = hex(&[1; 16]);
    assert_eq!(rest["members"][&named]["name"], "lab-a", "{rest}");
    assert_eq!(
        rest["members"][&named]["member_id"],
        "01a1b9de-8738-736e-9fff-609509b3fcbb"
    );
    assert!(
        rest["members"].get(hex(&[2; 16])).is_none(),
        "a producer nobody names is left out"
    );
    assert_eq!(
        rest["records"].as_array().map(Vec::len),
        Some(5),
        "the records untouched"
    );

    let mut request = tonic::Request::new(crate::v1::ListRecordsRequest {
        zone: ZONE.to_owned(),
        ledger: LEDGER.to_owned(),
        ..Default::default()
    });
    request.extensions_mut().insert(actor);
    let grpc = EventLog::list_records(&facade, request)
        .await
        .expect("answered")
        .into_inner();
    let over_grpc: serde_json::Value = grpc
        .members
        .iter()
        .map(|member| {
            (
                member.host_id.clone(),
                json!({"member_id": member.member_id, "name": member.name}),
            )
        })
        .collect::<serde_json::Map<_, _>>()
        .into();
    assert_eq!(
        over_grpc, rest["members"],
        "REST and gRPC name the same members"
    );
    assert_eq!(grpc.records.len(), 5);
}
