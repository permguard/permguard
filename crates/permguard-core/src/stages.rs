// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The stage of every interface id this build serves, and the header its discovery document
//! carries (WP-7.4a, owner decisions of 2026-10-21).
//!
//! | Stage        | Meaning                                                                      |
//! | ------------ | ---------------------------------------------------------------------------- |
//! | `v1alpha1`   | experimental, served only with explicit opt-in                               |
//! | `v1`         | stable: additive changes only                                                |
//! | `deprecated` | still served; discovery carries `stage` and `sunset`                         |
//! | `retired`    | refused with `interface_retired`, never upgraded to another id               |
//!
//! Every interface document starts with the same [`Header`]: the product version `/version`
//! publishes, the component serving it, that component's lifecycle phase, and the interface's
//! stage, with `sunset` when it is deprecated. The plane document lists every served id with its
//! stage too. A client that names a retired id receives the refusal, from its discovery document
//! and from the load gate of a manifest that binds it.

use serde::{Deserialize, Serialize};

use crate::api::{ApiError, ErrorClass};
use crate::codes;
use crate::domains::interface;
use crate::lifecycle::Phase;

/// Where an interface id stands in its lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stage {
    V1Alpha1,
    V1,
    /// Still served, until the RFC 3339 instant it names.
    Deprecated {
        sunset: &'static str,
    },
    Retired,
}

impl Stage {
    /// The stage as every document spells it.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::V1Alpha1 => "v1alpha1",
            Self::V1 => "v1",
            Self::Deprecated { .. } => "deprecated",
            Self::Retired => "retired",
        }
    }

    /// When a deprecated id stops being served.
    pub fn sunset(self) -> Option<&'static str> {
        match self {
            Self::Deprecated { sunset } => Some(sunset),
            _ => None,
        }
    }
}

/// One registered interface id and its stage.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Registered {
    pub id: &'static str,
    pub stage: Stage,
}

/// Every interface id this build has served, with its stage today: none deprecated or retired.
pub const REGISTRY: &[Registered] = &[
    Registered {
        id: interface::PDP_NATIVE_V1,
        stage: Stage::V1,
    },
    Registered {
        id: interface::PDP_TEMPORAL_V1ALPHA1,
        stage: Stage::V1Alpha1,
    },
    Registered {
        id: interface::DECISIONS_NATIVE_V1,
        stage: Stage::V1,
    },
    Registered {
        id: interface::EVENTS_NATIVE_V1ALPHA1,
        stage: Stage::V1Alpha1,
    },
];

/// The id `id` of `registry` when it is served: a retired one is refused `interface_retired`,
/// class `validation`, and never answered under another id; one the registry does not hold is
/// `not_found`.
pub fn served_in<'a>(registry: &'a [Registered], id: &str) -> Result<&'a Registered, ApiError> {
    let registered = registry
        .iter()
        .find(|entry| entry.id == id)
        .ok_or_else(|| {
            ApiError::new(
                ErrorClass::NotFound,
                codes::common::NOT_FOUND,
                format!("`{id}` is not an interface this build registers"),
            )
        })?;
    if registered.stage == Stage::Retired {
        return Err(ApiError::new(
            ErrorClass::Validation,
            codes::common::INTERFACE_RETIRED,
            format!("`{id}` is retired: it is no longer served, and no other id answers for it"),
        ));
    }
    Ok(registered)
}

/// [`served_in`] this build's [`REGISTRY`].
pub fn served(id: &str) -> Result<&'static Registered, ApiError> {
    served_in(REGISTRY, id)
}

/// The ids of `ids` that `registry` holds as retired.
pub fn retired_in<'a>(
    registry: &[Registered],
    ids: impl IntoIterator<Item = &'a str>,
) -> Vec<String> {
    ids.into_iter()
        .filter(|id| {
            registry
                .iter()
                .any(|entry| entry.id == *id && entry.stage == Stage::Retired)
        })
        .map(str::to_owned)
        .collect()
}

/// What every interface document starts with.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Header {
    /// The product version, as `/version` publishes it: empty where the deployment does not
    /// disclose its build.
    pub version: String,
    /// `control-plane` or `data-plane`.
    pub component: String,
    /// The serving component's lifecycle phase.
    pub state: String,
    /// `v1alpha1`, `v1` or `deprecated`.
    pub stage: String,
    /// When a deprecated interface stops being served, RFC 3339.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sunset: Option<String>,
}

impl Header {
    /// The header of the served interface `registered`, from `component` in `phase`.
    pub fn of(registered: &Registered, component: &str, version: &str, phase: Phase) -> Self {
        Self {
            version: version.to_owned(),
            component: component.to_owned(),
            state: phase.as_str().to_owned(),
            stage: registered.stage.as_str().to_owned(),
            sunset: registered.stage.sunset().map(str::to_owned),
        }
    }
}

/// What a plane hands each interface document it serves: who it is, what build it publishes, and
/// where to read its phase from.
#[derive(Debug, Clone)]
pub struct Describer {
    component: &'static str,
    version: String,
    phase: PhaseSource,
    /// The registry the header is looked up in: this build's, unless a test hands another.
    registry: &'static [Registered],
}

/// Where a describer reads the phase: the running plane's health, or a fixed one.
#[derive(Debug, Clone)]
enum PhaseSource {
    Plane(crate::plane::PlaneHealth),
    Fixed(Phase),
}

impl Describer {
    /// The describer of `component`, publishing `version`, its phase read from `health`.
    pub fn new(
        component: &'static str,
        version: String,
        health: crate::plane::PlaneHealth,
    ) -> Self {
        Self {
            component,
            version,
            phase: PhaseSource::Plane(health),
            registry: REGISTRY,
        }
    }

    /// The describer of the plane `context` serves as `component`: the version `/version`
    /// publishes, empty where the deployment does not disclose its build.
    pub fn of_plane(context: &crate::plane::PlaneContext<'_>, component: &'static str) -> Self {
        let version = if context.config().disclose_build() {
            context.config().version().to_owned()
        } else {
            String::new()
        };
        Self::new(component, version, context.health())
    }

    /// A describer of `component` attached to no running process: its phase is the one an empty
    /// lifecycle reports, `bootstrap`, and it publishes no version. For tests and tools that
    /// render a document outside a server.
    pub fn detached(component: &'static str) -> Self {
        Self {
            component,
            version: String::new(),
            phase: PhaseSource::Fixed(Phase::Bootstrap),
            registry: REGISTRY,
        }
    }

    /// This describer, looking ids up in `registry`: what a test retiring an id hands.
    pub fn with_registry(mut self, registry: &'static [Registered]) -> Self {
        self.registry = registry;
        self
    }

    /// The header of the interface `id` now, or its refusal when it is retired.
    pub fn header(&self, id: &str) -> Result<Header, ApiError> {
        let registered = served_in(self.registry, id)?;
        Ok(Header::of(
            registered,
            self.component,
            &self.version,
            self.phase(),
        ))
    }

    /// The component's phase now.
    pub fn phase(&self) -> Phase {
        match &self.phase {
            PhaseSource::Plane(health) => health.phase(),
            PhaseSource::Fixed(phase) => *phase,
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;

    /// WP-7.4a, owner decision of 2026-10-21: every interface this build serves is listed with its
    /// stage, none deprecated or retired today.
    #[test]
    fn every_served_interface_is_listed_with_its_stage() {
        let stages: Vec<(&str, &str)> = REGISTRY
            .iter()
            .map(|entry| (entry.id, entry.stage.as_str()))
            .collect();
        assert_eq!(
            stages,
            vec![
                ("permguard.api.pdp.native.v1", "v1"),
                ("permguard.api.pdp.temporal.v1alpha1", "v1alpha1"),
                ("permguard.api.decisions.native.v1", "v1"),
                ("permguard.api.events.native.v1alpha1", "v1alpha1"),
            ]
        );
        for entry in REGISTRY {
            assert_eq!(served(entry.id).expect("served").id, entry.id);
        }
        assert_eq!(
            served(interface::PDP_V1_LEGACY)
                .expect_err("a legacy spelling is no interface of its own")
                .code(),
            codes::common::NOT_FOUND
        );
    }

    /// WP-7.4a, owner decision of 2026-10-21: a deprecated interface is served and publishes its
    /// sunset in its header.
    #[test]
    fn a_deprecated_interface_publishes_its_sunset() {
        let registry = [Registered {
            id: "permguard.api.old.v1",
            stage: Stage::Deprecated {
                sunset: "2027-06-30T00:00:00Z",
            },
        }];
        let registered = served_in(&registry, "permguard.api.old.v1").expect("still served");
        let header = Header::of(registered, "data-plane", "0.1.0", Phase::Serving);
        assert_eq!(header.stage, "deprecated");
        assert_eq!(header.sunset.as_deref(), Some("2027-06-30T00:00:00Z"));
        assert_eq!(header.state, "serving");
        assert_eq!(header.component, "data-plane");
        assert_eq!(header.version, "0.1.0");
        let v1 = Header::of(&REGISTRY[0], "data-plane", "", Phase::Ready);
        assert_eq!((v1.sunset, v1.version.as_str()), (None, ""));
        assert_eq!(v1.state, "ready", "the phase it is given, whichever it is");
    }

    /// WP-7.4a, owner decision of 2026-10-21: a retired id is refused `interface_retired`, class
    /// `validation`, `400`, never answered under another id.
    #[test]
    fn a_retired_interface_is_refused_never_upgraded() {
        let registry = [
            Registered {
                id: "permguard.api.gone.v1",
                stage: Stage::Retired,
            },
            Registered {
                id: "permguard.api.gone.v2",
                stage: Stage::V1,
            },
        ];
        let refused = served_in(&registry, "permguard.api.gone.v1").expect_err("retired");
        assert_eq!(refused.code(), codes::common::INTERFACE_RETIRED);
        assert_eq!(refused.class(), ErrorClass::Validation);
        assert_eq!(refused.http_status(), 400);
        assert!(served_in(&registry, "permguard.api.gone.v2").is_ok());
        assert_eq!(
            retired_in(
                &registry,
                ["permguard.api.gone.v2", "permguard.api.gone.v1"]
            ),
            vec!["permguard.api.gone.v1".to_owned()]
        );
        assert!(retired_in(REGISTRY, REGISTRY.iter().map(|entry| entry.id)).is_empty());
    }
}
