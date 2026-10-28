// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! Closed JSON documents consumed by the Host CLI.

use serde::{Deserialize, Serialize};

use super::members::{CoordinatorView, NarrowView};

/// The invitation handoff printed once by `host members invite create`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InvitationHandoff {
    pub version: u64,
    pub coordinator: CoordinatorView,
    pub invite_id: String,
    pub token: String,
    pub requested: NarrowView,
    pub expires: String,
}

/// The versioned local identity-pin store.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct PinStore {
    pub version: u64,
    pub pins: Vec<IdentityPin>,
}

/// One exact administrative endpoint, Host id and identity fingerprint pin.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IdentityPin {
    pub url: String,
    pub host_id: String,
    pub fingerprint: String,
}
