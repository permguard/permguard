// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! `GET /host/v1/status`: the phase of the Host, every Plane and every service, with reasons
//! and `stalled_since`, and the assurance profile the volume runs under. Under `lifecycle.read`.
//!
//! The members that may be absent are always present and `null` when they are: both transports
//! render the same document, and the cross-transport vectors compare them byte for byte.

use serde::{Deserialize, Serialize};

use permguard_core::authz::{Actor, operations};
use permguard_core::lifecycle::{ComponentReport, Degraded, HOST};

use super::{HostApi, Refusal};

/// The assurance block (WP-2.8): the profile, how it is enforced, the higher controls added and
/// the relaxations in force; the same block the process discovery document publishes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Assurance {
    /// `development`, `production` or `regulated`.
    pub profile: String,
    /// Always `local`: the Host enforces its profile, it does not attest it.
    pub enforcement: String,
    /// Controls of a higher profile the deployment switched on.
    pub added_controls: Vec<String>,
    /// Relaxations the values in force amount to, each one the profile permits.
    pub relaxations: Vec<String>,
}

impl Assurance {
    /// The block from the core's report.
    pub fn of(report: &permguard_core::assurance::AssuranceReport) -> Self {
        Self {
            profile: report.profile.to_owned(),
            enforcement: report.enforcement.to_owned(),
            added_controls: report
                .added_controls
                .iter()
                .map(|c| (*c).to_owned())
                .collect(),
            relaxations: report.relaxations.iter().map(|r| (*r).to_owned()).collect(),
        }
    }
}

/// One capability served without its backing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DegradedView {
    pub capability: String,
    pub reason: String,
}

impl From<Degraded> for DegradedView {
    fn from(degraded: Degraded) -> Self {
        Self {
            capability: degraded.capability,
            reason: degraded.reason,
        }
    }
}

/// One component of the process, as the health document reports it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ComponentView {
    pub component: String,
    pub kind: String,
    pub state: String,
    pub required: bool,
    pub stalled_since: Option<String>,
    pub last_success: Option<String>,
    pub next_attempt: Option<String>,
    pub reason: Option<String>,
}

impl From<ComponentReport> for ComponentView {
    fn from(report: ComponentReport) -> Self {
        Self {
            component: report.component,
            kind: report.kind.to_owned(),
            state: report.state.to_owned(),
            required: report.required,
            stalled_since: report.stalled_since,
            last_success: report.last_success,
            next_attempt: report.next_attempt,
            reason: report.reason,
        }
    }
}

/// What the status route answers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StatusView {
    pub live: bool,
    pub ready: bool,
    /// The Host's phase.
    pub state: String,
    pub degraded: Vec<DegradedView>,
    pub components: Vec<ComponentView>,
    pub assurance: Assurance,
}

impl HostApi {
    /// `GET /host/v1/status`.
    pub fn status(&self, actor: &Actor) -> Result<StatusView, Refusal> {
        let _admitted = self.admit(actor, operations::LIFECYCLE_READ)?;
        Ok(self.status_view())
    }

    /// The status document, once the caller is admitted.
    fn status_view(&self) -> StatusView {
        let report = self.health.lifecycle().report(HOST);
        StatusView {
            live: self.health.is_live(),
            ready: self.health.is_ready(),
            state: report.state.to_owned(),
            degraded: report.degraded.into_iter().map(Into::into).collect(),
            components: report.components.into_iter().map(Into::into).collect(),
            assurance: self.assurance.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;
    use crate::api::testing::{actor, admin, facade};

    #[test]
    fn the_status_names_the_host_phase_and_is_gated() {
        let api = facade("status");
        let status = api.status(&admin()).expect("the administrator reads it");
        assert_eq!(status.assurance.profile, "development");
        assert!(status.components.iter().any(|c| c.component == HOST));
        assert_eq!(status.state, status.components[0].state);
        let json = serde_json::to_value(&status).expect("serializes");
        assert!(
            json["components"][0].get("stalled_since").is_some(),
            "absent members are present and null: {json}"
        );
        let refused = api
            .status(&actor("spiffe://acme/reader"))
            .expect_err("no grant");
        assert!(matches!(refused, Refusal::Denied(_)));
    }
}
