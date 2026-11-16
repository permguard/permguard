// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! One REST request, and either its payload or the refusal every Permguard API answers with.

// A helper every surface shares is idle in a build that selects the few that do not call it.
#![cfg_attr(not(feature = "full"), allow(dead_code, unused_imports))]

use serde::Deserialize;

use crate::endpoint::Endpoint;
use crate::failure::Failure;
use crate::http::Client;

/// What the server says when it refuses: the shape every Permguard API shares.
#[derive(Debug, Deserialize)]
struct Refusal {
    class: String,
    code: String,
    message: String,
}

/// Sends one request and reads back either the payload or the refusal.
pub(crate) fn call<T: for<'de> Deserialize<'de>>(
    client: &Client,
    endpoint: &Endpoint,
    method: &str,
    path: &str,
    body: Option<&str>,
) -> Result<T, Failure> {
    let response = client
        .request(endpoint, method, path, body)
        .map_err(|error| Failure {
            class: "unavailable".to_owned(),
            reason: error.reason().to_owned(),
            detail: error.to_string(),
            usage: false,
        })?;

    if (200..300).contains(&response.status) {
        return serde_json::from_str(&response.body).map_err(|error| Failure {
            class: "internal".to_owned(),
            reason: permguard_core::codes::client::DECODE_FAILED.to_owned(),
            detail: format!("the answer to {method} {path} was unreadable: {error}"),
            usage: false,
        });
    }

    // A refusal carries its class, its code and a sentence; anything else gets the status as both.
    match serde_json::from_str::<Refusal>(&response.body) {
        Ok(refusal) => Err(Failure {
            // The class decides whose mistake it is: validation, conflicts and lookups are the
            // operator's to fix; unavailable and internal are the world's.
            usage: matches!(
                refusal.class.as_str(),
                "validation" | "conflict" | "not_found"
            ),
            class: refusal.class,
            reason: refusal.code,
            detail: refusal.message,
        }),
        // A denial at the listener's gate (TC-1): `{code, message}` and no class, as the wire
        // carries it; the operator's to fix, as over gRPC.
        Err(_) => match serde_json::from_str::<permguard_core::api::WireDenial>(&response.body) {
            Ok(denial) if matches!(response.status, 401 | 403) => Err(Failure {
                class: String::new(),
                reason: denial.code,
                detail: denial.message,
                usage: true,
            }),
            _ => Err(Failure {
                class: "internal".to_owned(),
                reason: permguard_core::codes::client::HTTP_STATUS.to_owned(),
                detail: format!("{method} {path} answered {}", response.status),
                usage: false,
            }),
        },
    }
}
