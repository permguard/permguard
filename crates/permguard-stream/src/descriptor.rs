// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! What a stream *is*, declared before anything runs: who owns it, which way it flows, where it
//! lives on disk.
//!
//! # Why streams are declared
//!
//! Every evidence stream in a process — the decision log, the temporal events, whatever a future
//! plane adds — owns a directory, a record domain and a direction. When each subsystem builds its
//! own journal and picks its own path, the first collision is discovered by the second writer,
//! at runtime, on somebody's volume. Declared up front, the same collision is a refusal at
//! startup while somebody is watching.
//!
//! A descriptor is deliberately small: identity, role, record domain, directory. What a stream
//! *does* — its schema, its cryptography, its API — stays with the plane that owns it. The
//! registry can therefore say "these two claims collide" without knowing what either stream
//! carries, which is exactly the separation that lets a new stream type register without asking
//! this crate to change.
//!
//! # Legacy directories
//!
//! The streams that predate this registry keep the directories they already write — moving
//! recorded evidence silently is not a thing this workspace does. They register with
//! `legacy: true`, and a nesting between two legacy directories is reported as [`Registered::
//! Tolerated`] rather than refused, so an existing volume keeps starting while the composition
//! logs what a future layout will separate. A collision involving any *new* stream is refused
//! outright: new mistakes are not grandfathered.

use std::collections::BTreeSet;
use std::fmt;
use std::path::{Path, PathBuf};

/// Which way a stream flows through this process.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Role {
    /// This process writes the stream and ships it.
    Producer,
    /// This process receives the stream and keeps it.
    Consumer,
}

impl Role {
    /// The path segment and log word for this role.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Producer => "producer",
            Self::Consumer => "consumer",
        }
    }
}

impl fmt::Display for Role {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// The stable name of one stream: the plane that serves it and the type it carries.
///
/// Both segments end up in paths and documents, so both are held to path-safe spelling:
/// lowercase ASCII, digits and hyphens, nothing else.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct StreamIdentity {
    plane: String,
    stream_type: String,
}

impl StreamIdentity {
    /// Names a stream, refusing a segment that could not travel in a path or a URL.
    pub fn new(plane: &str, stream_type: &str) -> Result<Self, RegistryError> {
        for (label, held) in [("plane", plane), ("stream type", stream_type)] {
            let shaped = !held.is_empty()
                && held
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
                && !held.starts_with('-')
                && !held.ends_with('-');
            if !shaped {
                return Err(RegistryError::Misshapen {
                    label,
                    held: held.to_owned(),
                });
            }
        }

        Ok(Self {
            plane: plane.to_owned(),
            stream_type: stream_type.to_owned(),
        })
    }

    /// The plane that serves this stream.
    pub fn plane(&self) -> &str {
        &self.plane
    }

    /// The type of record this stream carries.
    pub fn stream_type(&self) -> &str {
        &self.stream_type
    }
}

impl fmt::Display for StreamIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}/{}", self.plane, self.stream_type)
    }
}

/// One stream, declared.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamDescriptor {
    /// Who serves it and what it carries.
    pub identity: StreamIdentity,
    /// Which way it flows through this process.
    pub role: Role,
    /// The record domain — e.g. `permguard.event.record.v1` — so two streams that must never be
    /// confused are visibly different here too.
    pub record_type: String,
    /// The directory this stream keeps its data under.
    pub directory: PathBuf,
    /// Whether the directory predates the versioned layout. Legacy directories keep working;
    /// what they lose is only the right to *new* collisions.
    pub legacy: bool,
    /// Whether this deployment turned the stream on. A disabled stream stays declared — and
    /// therefore discoverable as disabled — because "not here" and "here, turned off" are
    /// different answers, and a caller deciding where to read needs the second one.
    pub enabled: bool,
}

impl StreamDescriptor {
    /// What discovery publishes about this stream: identity, direction, contract, state.
    ///
    /// Deliberately not the whole descriptor — the directory is this process's own business, and
    /// a discovery document that leaked filesystem layout would be volunteering a map.
    pub fn public_view(&self) -> serde_json::Value {
        serde_json::json!({
            "plane": self.identity.plane(),
            "stream_type": self.identity.stream_type(),
            "role": self.role.as_str(),
            "record_type": self.record_type,
            "enabled": self.enabled,
        })
    }
}

/// What registering a descriptor concluded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Registered {
    /// Registered cleanly.
    Clean,
    /// Registered, but its directory nests with another legacy stream's — a fragility the
    /// composition should log, and the versioned layout exists to remove.
    Tolerated { with: String },
}

/// Why a descriptor was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegistryError {
    /// A name that could not travel in a path or a URL.
    Misshapen { label: &'static str, held: String },
    /// The same stream and role declared twice is two subsystems claiming one stream.
    Duplicate { identity: String, role: Role },
    /// Two streams sharing or nesting directories, at least one of them new.
    Collision {
        held: String,
        offered: String,
        directory: String,
    },
}

impl fmt::Display for RegistryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Misshapen { label, held } => write!(
                formatter,
                "`{held}` cannot name a stream {label}: lowercase ASCII, digits and inner \
                 hyphens are what travels in a path and a URL"
            ),
            Self::Duplicate { identity, role } => write!(
                formatter,
                "the {role} stream `{identity}` is declared twice: one stream has one owner"
            ),
            Self::Collision {
                held,
                offered,
                directory,
            } => write!(
                formatter,
                "`{offered}` claims `{directory}`, which `{held}` already writes under: two \
                 streams sharing a directory tree will eventually read each other's files"
            ),
        }
    }
}

impl std::error::Error for RegistryError {}

/// Every stream this process serves, declared at composition and checked once.
#[derive(Debug, Default)]
pub struct StreamRegistry {
    streams: Vec<StreamDescriptor>,
}

impl StreamRegistry {
    /// A registry with nothing declared.
    pub fn new() -> Self {
        Self::default()
    }

    /// Declares one stream, refusing duplicates and directory collisions.
    pub fn register(&mut self, descriptor: StreamDescriptor) -> Result<Registered, RegistryError> {
        if self
            .streams
            .iter()
            .any(|held| held.identity == descriptor.identity && held.role == descriptor.role)
        {
            return Err(RegistryError::Duplicate {
                identity: descriptor.identity.to_string(),
                role: descriptor.role,
            });
        }

        let mut tolerated = None;
        for held in &self.streams {
            if !entangled(&held.directory, &descriptor.directory) {
                continue;
            }
            if held.legacy && descriptor.legacy {
                // Both predate the layout: the volume already looks like this, and refusing it
                // would refuse every existing deployment. Reported, so the composition can say so.
                tolerated = Some(held.identity.to_string());
                continue;
            }

            return Err(RegistryError::Collision {
                held: held.identity.to_string(),
                offered: descriptor.identity.to_string(),
                directory: descriptor.directory.display().to_string(),
            });
        }

        let outcome = match tolerated {
            Some(with) => Registered::Tolerated { with },
            None => Registered::Clean,
        };
        self.streams.push(descriptor);

        Ok(outcome)
    }

    /// Every declared stream, in declaration order.
    pub fn streams(&self) -> &[StreamDescriptor] {
        &self.streams
    }

    /// The declared stream types of one plane, for a surface that lists what it serves.
    pub fn types_of(&self, plane: &str) -> BTreeSet<&str> {
        self.streams
            .iter()
            .filter(|held| held.identity.plane() == plane)
            .map(|held| held.identity.stream_type())
            .collect()
    }

    /// One plane's declaration of one stream type, when it made one.
    pub fn find(&self, plane: &str, stream_type: &str) -> Option<&StreamDescriptor> {
        self.streams.iter().find(|held| {
            held.identity.plane() == plane && held.identity.stream_type() == stream_type
        })
    }
}

/// Whether one directory is the other, or contains it.
///
/// Purely lexical, on the paths as declared: the check runs at startup, before either directory
/// necessarily exists, so there is nothing to canonicalize against. Two spellings of one
/// directory that only the filesystem knows are equal are a mistake this cannot catch — and the
/// same mistake the colliding writers would then make in each other's favour.
fn entangled(one: &Path, other: &Path) -> bool {
    one == other || one.starts_with(other) || other.starts_with(one)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn descriptor(
        plane: &str,
        stream_type: &str,
        directory: &str,
        legacy: bool,
    ) -> StreamDescriptor {
        StreamDescriptor {
            identity: StreamIdentity::new(plane, stream_type).unwrap(),
            role: Role::Producer,
            record_type: format!("permguard.{stream_type}.record.v1"),
            directory: PathBuf::from(directory),
            legacy,
            enabled: true,
        }
    }

    #[test]
    fn distinct_streams_register_cleanly() {
        let mut registry = StreamRegistry::new();

        assert_eq!(
            registry.register(descriptor(
                "data-plane",
                "decisions",
                "data/streams/data-plane/decisions",
                false
            )),
            Ok(Registered::Clean)
        );
        assert_eq!(
            registry.register(descriptor(
                "data-plane",
                "events",
                "data/streams/data-plane/events",
                false
            )),
            Ok(Registered::Clean)
        );
        assert_eq!(registry.streams().len(), 2);
        assert_eq!(
            registry
                .types_of("data-plane")
                .into_iter()
                .collect::<Vec<_>>(),
            ["decisions", "events"]
        );
    }

    #[test]
    fn the_same_stream_declared_twice_is_refused() {
        let mut registry = StreamRegistry::new();
        registry
            .register(descriptor("data-plane", "events", "a", false))
            .unwrap();

        let refused = registry.register(descriptor("data-plane", "events", "b", false));
        assert!(
            matches!(refused, Err(RegistryError::Duplicate { .. })),
            "{refused:?}"
        );
    }

    #[test]
    fn a_producer_and_a_consumer_of_the_same_stream_coexist() {
        // One process can ship a stream and another plane in the same process can keep it —
        // the all-in-one does exactly this. Same identity, different role, different directory.
        let mut registry = StreamRegistry::new();
        registry
            .register(descriptor("data-plane", "events", "a", false))
            .unwrap();

        let mut consumer = descriptor("data-plane", "events", "b", false);
        consumer.role = Role::Consumer;
        assert_eq!(registry.register(consumer), Ok(Registered::Clean));
    }

    #[test]
    fn a_nested_directory_involving_a_new_stream_is_refused() {
        let mut registry = StreamRegistry::new();
        registry
            .register(descriptor("data-plane", "events", "data/events", true))
            .unwrap();

        // The new stream nesting under a legacy root is a new mistake, not a grandfathered one.
        let refused = registry.register(descriptor(
            "control-plane",
            "events",
            "data/events/store",
            false,
        ));
        assert!(
            matches!(refused, Err(RegistryError::Collision { .. })),
            "{refused:?}"
        );
    }

    #[test]
    fn two_legacy_directories_that_nest_are_tolerated_and_named() {
        // The shape existing volumes already have: the control plane's event store sits under
        // the root the data plane journals in. It keeps starting, and the composition is told.
        let mut registry = StreamRegistry::new();
        registry
            .register(descriptor("data-plane", "events", "data/events", true))
            .unwrap();

        let mut consumer = descriptor("control-plane", "events", "data/events/store", true);
        consumer.role = Role::Consumer;
        assert_eq!(
            registry.register(consumer),
            Ok(Registered::Tolerated {
                with: "data-plane/events".to_owned()
            })
        );
    }

    #[test]
    fn a_name_that_cannot_travel_is_refused() {
        for held in ["", "Data", "a b", "a/b", "-a", "a-", "café"] {
            assert!(
                StreamIdentity::new(held, "events").is_err(),
                "`{held}` is not a plane name"
            );
        }
        assert!(StreamIdentity::new("data-plane", "decision-logs").is_ok());
    }
}
