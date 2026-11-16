// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! What a composition wires for the Planes it runs, whoever serves them: the structured sections
//! of the configuration a Plane owns, and the registration of the streams it declares.
//!
//! One implementation for a server, which serves its Planes on listeners, and for an application
//! that embeds one with none: the configuration a Plane reads is the same file, read the same way.

use anyhow::Result;
use permguard_core::planes::settings;
use permguard_core::{Config, Value};

/// The Control Plane's structured configuration: the producer keys it verifies decisions and
/// events under, and what its decision store accepts in clear.
pub fn control_plane_section(config: Config, value: &Value) -> Result<Config> {
    let config = config.with_decision_producer_keys(settings::producer_keys(value)?);
    let config = config.with_decision_accept(settings::decision_accept(value)?)?;

    Ok(config.with_event_producer_keys(settings::event_producer_keys(value)?))
}

/// The Data Plane's structured configuration. Its `mirrors` lists and `decisions.log.server` are
/// lists and structures, so they cannot ride the setting layers: they are attached as structured
/// configuration, and their shape is checked while somebody is watching.
pub fn data_plane_section(config: Config, value: &Value) -> Result<Config> {
    let config = config.with_mirror_local(settings::mirror_local(value)?);
    let config = config.with_mirror_task_selections(settings::mirror_task_selections(value)?)?;
    let config = config.with_mirror_aliases(settings::mirror_aliases(value)?)?;
    // The subscriptions this plane imports history from: a list of three-part entries, so it
    // travels here rather than through the setting layers.
    let config = config.with_pull_ledgers(settings::pull_ledgers(value)?);
    let config = config.with_pull_producer_keys(settings::pull_producer_keys(value)?);
    let config = config.with_events_destination(settings::events_destination(value)?)?;
    let (destination, include) = settings::log_destination(value)?;

    config.with_log_destination(destination, include)
}

/// The streams one selected Plane declares, with how its records name it.
pub struct DeclaredStreams {
    /// The component name the Plane's records carry.
    pub component: &'static str,
    /// The Plane, as a refusal names it.
    pub description: &'static str,
    /// Every stream it declares under the configuration, enabled or not.
    pub streams: Vec<permguard_stream::StreamDescriptor>,
}

/// Registers every stream every selected Plane declares, once — a validation pass, by design: the
/// registry lives for this check and is dropped with it. What it buys is that the first directory
/// collision is a refusal at startup rather than a runtime surprise on a volume.
///
/// A nesting between two directories that predate the versioned layout is tolerated and logged —
/// an existing volume keeps starting — and anything involving a new stream is refused outright.
/// The versioned layout is then claimed before any stream serves: the marker under `data/streams`
/// says which rule the directories below it follow, and a root laid out by a rule this build does
/// not know is refused rather than guessed at.
pub fn register_streams(config: &Config, planes: Vec<DeclaredStreams>) -> Result<()> {
    let mut registry = permguard_stream::StreamRegistry::new();
    let mut serving_any = false;
    for plane in planes {
        for descriptor in plane.streams {
            // A disabled stream is declared — discovery lists it as disabled — but it owns no
            // directory and registers nothing: only writers can collide.
            if !descriptor.enabled {
                continue;
            }
            serving_any = true;
            let identity = descriptor.identity.to_string();
            match registry.register(descriptor) {
                Ok(permguard_stream::Registered::Clean) => {}
                Ok(permguard_stream::Registered::Tolerated { with }) => tracing::warn!(
                    event.name = "streams.legacy_nesting",
                    component = plane.component,
                    stream = %identity,
                    beside = %with,
                    "two pre-layout streams nest their directories; the versioned \
                     layout under data/streams separates what a future migration moves"
                ),
                Err(refused) => anyhow::bail!(
                    "registering the streams of the {}: {refused}",
                    plane.description
                ),
            }
        }
    }

    if serving_any {
        permguard_stream::layout::claim(&config.data_directory())
            .map_err(|error| anyhow::anyhow!("claiming the stream layout: {error}"))?;
    }

    Ok(())
}
