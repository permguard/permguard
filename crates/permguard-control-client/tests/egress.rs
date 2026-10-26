// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! TS-4: the clients this crate builds never reach the network from a decision. Inside the
//! decision path's scope a call is refused before a name is resolved or a socket opened, over HTTP
//! and over gRPC alike, and counted; outside it nothing changes.

#![allow(clippy::expect_used)]

use permguard_control_client::narrate::Silent;
use permguard_control_client::pdp;
use permguard_control_client::tls::TlsOptions;

fn payload() -> serde_json::Value {
    serde_json::json!({
        "zone": "z", "ledger": "l",
        "subject": {"type": "user", "id": "u"},
        "resource": {"type": "document", "id": "d"},
        "action": {"name": "read"},
    })
}

#[test]
fn a_decision_reaches_no_plane_over_http_or_grpc() {
    // A decision's future, polled by a runtime of the test's own; the clients are built and
    // dropped outside it, as a caller of these blocking clients does.
    let runtime = tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("a runtime");
    // A port nothing listens on: reached, the call would fail differently, and later.
    for endpoint in ["http://127.0.0.1:9", "grpc://127.0.0.1:9"] {
        let client = pdp::client(endpoint, &TlsOptions::default(), Box::new(Silent))
            .expect("a client is built without dialling");
        let before = permguard_core::egress::refusals();
        let refused = runtime
            .block_on(permguard_core::egress::decision(async {
                client.evaluate(&payload())
            }))
            .expect_err("refused on the decision path");
        assert!(
            refused.detail.contains("decision path"),
            "{endpoint}: {}",
            refused.detail
        );
        assert!(
            permguard_core::egress::refusals() > before,
            "{endpoint}: counted"
        );
        drop(client);
    }
}
