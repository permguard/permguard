// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The Data Plane as a Plane of the Host: what it declares, the evidence streams it produces,
//! what it requires of a configuration, and the work it runs beside whatever serves it. Its routes,
//! on both transports, are `permguard-data-plane-server`'s.

/// What this plane declares to the Host under `config`.
pub fn declaration(config: &permguard_core::Config) -> permguard_host::composition::Declaration {
    crate::handles::declaration(config)
}

/// The evidence streams this plane serves under `config`, enabled or not: those of the evidence
/// this build carries.
#[cfg(any(feature = "decision-evidence", feature = "event-evidence"))]
pub fn streams(config: &permguard_core::Config) -> Vec<permguard_stream::StreamDescriptor> {
    let mut streams = Vec::new();

    // Declared whether or not the deployment turned them on: "not here" and "here, turned
    // off" are different answers, and discovery serves the second one too. Only enabled
    // streams own their directories.

    // The decision log: this plane produces it into a local spool and ships it. The spool
    // directory predates the versioned layout and stays where recorded evidence already is.
    #[cfg(feature = "decision-evidence")]
    if let Ok(identity) = permguard_stream::StreamIdentity::new("data-plane", "decisions") {
        streams.push(permguard_stream::StreamDescriptor {
            identity,
            role: permguard_stream::Role::Producer,
            record_type: permguard_core::domains::record::DECISION_V1.to_owned(),
            directory: config.working_dir().join(config.log_spool_directory()),
            legacy: true,
            enabled: config.log_enabled(),
        });
    }

    // The temporal events: journals per ledger under the events root, produced and shipped.
    #[cfg(feature = "event-evidence")]
    if let Ok(identity) = permguard_stream::StreamIdentity::new("data-plane", "events") {
        streams.push(permguard_stream::StreamDescriptor {
            identity,
            role: permguard_stream::Role::Producer,
            record_type: permguard_events::RECORD_TYPE.to_owned(),
            directory: config.events_directory(),
            legacy: true,
            enabled: crate::temporal::served(config),
        });
    }

    streams
}

/// What this plane requires before it binds anything.
pub fn startup_check(config: &permguard_core::Config) -> anyhow::Result<()> {
    // A Data Plane decides with the languages its build selected, and one built with none can
    // serve no ledger: an invalid profile is refused here rather than at the first load.
    if permguard_languages::languages().is_empty() {
        anyhow::bail!(
            "this build carries no policy language: a Data Plane is built with at least one of \
             the `cedar`, `rego` and `dogwood` features"
        );
    }
    // The languages this binary carries, before any ledger is loaded against them (LANG-12).
    permguard_languages::registry::check_registry().map_err(|collision| {
        anyhow::anyhow!("this build's language catalogue is inconsistent: {collision}")
    })?;
    // Retired (iteration 02, WP-10.4): decisions are shipped by the Host over
    // `decisions.ship`, to the coordinator its membership names; no plane names a server.
    if config.log_destination().is_some() {
        anyhow::bail!(
            "`dataPlane.decisions.log.server` is retired: decisions are shipped by the Host \
             over `decisions.ship` to the coordinator of its membership. Remove it"
        );
    }
    // A capability this build does not carry is refused by name, never ignored.
    #[cfg(not(feature = "decision-evidence"))]
    if config.log_enabled() {
        anyhow::bail!(
            "`dataPlane.decisions.log.enabled` is on and this build keeps no decision log: build \
             the Data Plane with the `decision-evidence` feature, or turn the log off"
        );
    }
    #[cfg(feature = "event-evidence")]
    crate::temporal::startup_check(config)?;
    #[cfg(not(feature = "event-evidence"))]
    {
        permguard_languages::registry::check_opted_in(config.experimental_named())
            .map_err(|error| anyhow::anyhow!(error))?;
        if config.events_enabled() {
            anyhow::bail!(
                "`dataPlane.events.enabled` is on and this build serves no temporal interface: \
                 build the Data Plane with the `event-evidence` feature, or turn the events off"
            );
        }
    }
    // The pool the partitions of a request fan out on holds no more workers than the evaluations
    // this deployment runs at once, and none under one: bound before anything decides (RD-17).
    permguard_languages::fanout::Fanout::bound_shared(config.evaluation_concurrency());
    Ok(())
}

/// Loops about the volume rather than the request, each off by default: the mirroring loop
/// keeps the policies current, the decision-log loop measures what this plane decided, and the
/// event loop keeps the history's floors. A plane fed by other means, or one that records
/// nothing, is a legitimate deployment.
// Each service is pushed under its own capability, so the list cannot be one literal.
#[allow(clippy::vec_init_then_push)]
pub fn services() -> Vec<Box<dyn permguard_core::PlaneTask>> {
    let mut services: Vec<Box<dyn permguard_core::PlaneTask>> = Vec::new();
    #[cfg(feature = "sync")]
    services.push(Box::new(crate::mirrors::MirrorService::new()));
    #[cfg(feature = "decision-evidence")]
    services.push(Box::new(crate::decisions::DecisionService::new()));
    services.push(Box::new(crate::authz::audit::DecisionAuditService::new()));
    // Off unless this plane serves the temporal interface: it keeps the floors and evicts
    // what no loaded policy still needs.
    #[cfg(feature = "event-evidence")]
    services.push(Box::new(crate::temporal::service::EventService::new()));
    services
}
