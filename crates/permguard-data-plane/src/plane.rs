// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The Data Plane as a Plane of the Host: what it declares, the evidence streams it produces,
//! what it requires of a configuration, and the work it runs beside whatever serves it. Its routes,
//! on both transports, are `permguard-data-plane-server`'s.

/// What this plane declares to the Host under `config`.
pub fn declaration(config: &permguard_core::Config) -> permguard_host::composition::Declaration {
    crate::handles::declaration(config)
}

/// The evidence streams this plane serves under `config`, enabled or not.
pub fn streams(config: &permguard_core::Config) -> Vec<permguard_stream::StreamDescriptor> {
    let mut streams = Vec::new();

    // Declared whether or not the deployment turned them on: "not here" and "here, turned
    // off" are different answers, and discovery serves the second one too. Only enabled
    // streams own their directories.

    // The decision log: this plane produces it into a local spool and ships it. The spool
    // directory predates the versioned layout and stays where recorded evidence already is.
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
    crate::temporal::startup_check(config)
}

/// Loops about the volume rather than the request, each off by default: the mirroring loop
/// keeps the policies current, the decision-log loop measures what this plane decided, and the
/// event loop keeps the history's floors. A plane fed by other means, or one that records
/// nothing, is a legitimate deployment.
pub fn services() -> Vec<Box<dyn permguard_core::PlaneTask>> {
    vec![
        Box::new(crate::mirrors::MirrorService::new()),
        Box::new(crate::decisions::DecisionService::new()),
        Box::new(crate::authz::audit::DecisionAuditService::new()),
        // Off unless this plane serves the temporal interface: it keeps the floors and evicts
        // what no loaded policy still needs.
        Box::new(crate::temporal::service::EventService::new()),
    ]
}
