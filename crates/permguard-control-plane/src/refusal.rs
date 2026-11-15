// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! What a facade answers instead of its payload, before any transport renders it: a domain refusal
//! or an access denial (WP-2.4). The answer each transport gives it is the server's.

use permguard_core::{AccessDenial, ApiError};

/// What a route answers instead of its payload: a domain refusal in the `{class, code, message}`
/// envelope, or an access denial in the closed `{code, message}` body the contract keeps apart
/// from it (WP-2.4). One type, so a facade function has one error path for both.
#[derive(Debug, Clone)]
pub enum Refusal {
    Api(ApiError),
    Denied(AccessDenial),
}

impl From<ApiError> for Refusal {
    fn from(error: ApiError) -> Self {
        Self::Api(error)
    }
}

impl From<AccessDenial> for Refusal {
    fn from(denial: AccessDenial) -> Self {
        Self::Denied(denial)
    }
}
