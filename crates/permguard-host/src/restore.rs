// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! Restore modes (WP-7.9, `1-architecture/8-architecture-storage-operations.md` restore modes, P9).
//!
//! A restore runs offline: the server stopped, `LOCK` held, the storage fence proven by a claim
//! generation above the one the snapshot's `BOOT` recorded, the volume scanned, then the mode's
//! identity transition.
//!
//! | Mode       | Identity       | Transition                                                                 |
//! | ---------- | -------------- | -------------------------------------------------------------------------- |
//! | `dr`       | same `host_id` | the next start mints a new boot id; every lease is the session's, fresh     |
//! | `forensic` | no serving     | the server refuses to start; the offline tools read the volume             |
//! | `clone`    | new `host_id`  | an emergency reset: no copied membership, lease or producer run starts     |
//!
//! ```text
//! host/RESTORE   view {1 v: 1, 2 mode, 3 at, 4 generation, 5 previous_boot_id, 6 plan_id}
//! ```
//!
//! The marker is written last, once the transition is done, as an operation of the mutation
//! transaction ([`record`]); it stays as the record of the restore. The plan the run consumes is
//! an operation of the same domain, [`PLAN`].

use std::collections::BTreeMap;

use permguard_objects::cbor::{self, Value};

use crate::identity::record::Boot;
use crate::operations::journal::{Initiator, OperationId};
use crate::operations::mutation::{
    Applied, Applying, Begin, Domain, Failure, MutationError, Mutations, Observed,
};
use crate::storage::volume::Volume;
use crate::storage::{StorageError, format, write};

/// The marker, in `host/`.
pub const MARKER: &str = "RESTORE";
/// The domain of the mutation transaction a restore's operations run in.
pub const DOMAIN: &str = "restore";
/// The plan step's operation.
pub const PLAN: &str = "restore.plan";
/// The run's operation: the marker written.
pub const RUN: &str = "restore.run";
/// The registered `security` actions of the two.
pub const AUDIT_PLANNED: &str = "host.restore.planned";
pub const AUDIT_RESTORED: &str = "host.restore.completed";
/// The record version this build writes and reads.
const VERSION: i64 = 1;

/// How a snapshot is restored.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// Disaster recovery: the same Host, a new incarnation.
    Dr,
    /// Read only: never served.
    Forensic,
    /// A new Host from the snapshot's data.
    Clone,
}

impl Mode {
    /// How the command line and the marker spell it.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Dr => "dr",
            Self::Forensic => "forensic",
            Self::Clone => "clone",
        }
    }

    /// The mode `text` names.
    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "dr" => Some(Self::Dr),
            "forensic" => Some(Self::Forensic),
            "clone" => Some(Self::Clone),
            _ => None,
        }
    }
}

/// What a restore recorded on the volume.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Marker {
    pub mode: Mode,
    /// When the restore ran, seconds.
    pub at: u64,
    /// The claim generation it ran under: the storage fence.
    pub generation: u64,
    /// The boot id the snapshot's `BOOT` recorded.
    pub previous_boot_id: [u8; 16],
    /// The plan the restore consumed.
    pub plan_id: [u8; 16],
}

fn uint(value: u64, what: &str) -> Result<Value, String> {
    i64::try_from(value)
        .map(Value::Int)
        .map_err(|_| format!("{what} is out of range"))
}

impl Marker {
    /// The canonical bytes.
    pub fn encode(&self) -> Result<Vec<u8>, String> {
        cbor::encode(&Value::Map(vec![
            (Value::Int(1), Value::Int(VERSION)),
            (Value::Int(2), Value::Text(self.mode.as_str().to_owned())),
            (Value::Int(3), uint(self.at, "the restore's time")?),
            (
                Value::Int(4),
                uint(self.generation, "the claim generation")?,
            ),
            (Value::Int(5), Value::Bytes(self.previous_boot_id.to_vec())),
            (Value::Int(6), Value::Bytes(self.plan_id.to_vec())),
        ]))
        .map_err(|error| error.to_string())
    }

    /// Reads the canonical bytes, closed: labels 1 to 6, the version first.
    pub fn decode(bytes: &[u8]) -> Result<Self, String> {
        const WHAT: &str = "a restore marker";
        let Value::Map(pairs) =
            cbor::decode_canonical(bytes).map_err(|error| format!("{WHAT}: {error}"))?
        else {
            return Err(format!("{WHAT} is a map"));
        };
        let mut held = BTreeMap::new();
        for (key, value) in pairs {
            match key {
                Value::Int(label) if (1..=6).contains(&label) => {
                    held.insert(label, value);
                }
                _ => return Err(format!("{WHAT} holds an unknown label")),
            }
        }
        match held.remove(&1) {
            Some(Value::Int(version)) if version == VERSION => {}
            Some(Value::Int(version)) => {
                return Err(format!(
                    "{WHAT} of version {version}, which this build does not read"
                ));
            }
            _ => return Err(format!("{WHAT} names no version")),
        }
        let text =
            |held: &mut BTreeMap<i64, Value>, label: i64, what: &str| match held.remove(&label) {
                Some(Value::Text(text)) => Ok(text),
                _ => Err(format!("{what} is text")),
            };
        let int =
            |held: &mut BTreeMap<i64, Value>, label: i64, what: &str| match held.remove(&label) {
                Some(Value::Int(value)) if value >= 0 => Ok(value as u64),
                _ => Err(format!("{what} is an unsigned integer")),
            };
        let id =
            |held: &mut BTreeMap<i64, Value>, label: i64, what: &str| match held.remove(&label) {
                Some(Value::Bytes(bytes)) => <[u8; 16]>::try_from(bytes.as_slice())
                    .map_err(|_| format!("{what} is 16 bytes")),
                _ => Err(format!("{what} is 16 bytes")),
            };
        let mode = text(&mut held, 2, "the mode")?;
        let marker = Self {
            mode: Mode::parse(&mode).ok_or_else(|| format!("`{mode}` is not a restore mode"))?,
            at: int(&mut held, 3, "the restore's time")?,
            generation: int(&mut held, 4, "the claim generation")?,
            previous_boot_id: id(&mut held, 5, "the previous boot id")?,
            plan_id: id(&mut held, 6, "the plan id")?,
        };
        if let Some(label) = held.keys().next() {
            return Err(format!("{WHAT} holds the unexpected label {label}"));
        }
        Ok(marker)
    }
}

/// The marker `volume` holds, if it was restored.
pub fn marked(volume: &Volume) -> Result<Option<Marker>, StorageError> {
    write::read_view(volume.host(), MARKER, format::VIEW)?
        .map(|bytes| Marker::decode(&bytes).map_err(StorageError::Corruption))
        .transpose()
}

/// Writes `marker` on `volume`, durably: the write of [`record`].
fn mark(volume: &Volume, marker: &Marker) -> Result<(), StorageError> {
    let body = marker.encode().map_err(StorageError::Corruption)?;
    write::replace_view(volume.host(), MARKER, format::VIEW, &body)
}

/// The target a run names: the plan it consumed, which the marker records.
fn run_target(plan_id: &[u8; 16]) -> String {
    format!("restore:{}", crate::identity::record::uuid_text(plan_id))
}

/// Records the restore `marker` describes, once its transition is done: the marker written as an
/// operation of the mutation transaction, audited `host.restore.completed`.
pub fn record(
    mutations: &Mutations,
    volume: &Volume,
    marker: &Marker,
    initiator: Initiator,
) -> Result<(), MutationError<StorageError>> {
    let target = Some(run_target(&marker.plan_id));
    mutations
        .run(
            Begin {
                domain: DOMAIN,
                operation: RUN,
                action: AUDIT_RESTORED,
                initiator,
                request: None,
                target: target.clone(),
            },
            |_applying: &Applying<'_>| {
                // A marker that may be half written is the recovery's to judge.
                mark(volume, marker).map_err(Failure::Indeterminate)?;
                Ok(Applied {
                    revision: marker.generation,
                    target,
                    value: (),
                })
            },
        )
        .map(|_| ())
}

/// A volume's restores as a domain of the mutation engine: a run shows applied once the marker
/// records the plan it names; a plan step shows nothing of its own, so one a crash interrupted is
/// failed and planned again.
pub struct Restores<'a>(pub &'a Volume);

impl Domain for Restores<'_> {
    fn name(&self) -> &'static str {
        DOMAIN
    }

    fn observe(&self, _operation_id: &OperationId, target: Option<&str>) -> Option<Observed> {
        // A marker that does not read shows nothing: the run is failed, and the corruption still
        // refuses every restore and every start that reads it.
        let marker = marked(self.0).ok()??;
        (target? == run_target(&marker.plan_id)).then(|| Observed {
            revision: marker.generation,
            target: Some(run_target(&marker.plan_id)),
        })
    }
}

/// The `BOOT` the snapshot's last start recorded: its boot id and the claim generation it ran
/// under.
pub fn previous_boot(volume: &Volume) -> Result<Option<Boot>, String> {
    let dir = volume
        .host()
        .subdir(crate::identity::DIRECTORY, false)
        .map_err(|error| format!("the identity directory: {error}"))?;
    dir.read(crate::identity::BOOT)
        .map_err(|error| format!("the identity's BOOT: {error}"))?
        .map(|bytes| Boot::decode(&bytes).map_err(|error| format!("the identity's BOOT: {error}")))
        .transpose()
}

/// The storage fence a restore proves (WP-7.9): the volume's claim generation exceeds the one the
/// snapshot's last start ran under, which only the recovery operator's `volume claim` raises.
/// Answers the snapshot's `BOOT`.
pub fn fence(volume: &Volume) -> Result<Boot, String> {
    let boot = previous_boot(volume)?.ok_or_else(|| {
        "the snapshot records no start (no `host/identity/BOOT`): there is no Host to restore"
            .to_owned()
    })?;
    if volume.generation() == boot.generation {
        return Err(format!(
            "the claim generation {} does not exceed the {} a start or an offline open already \
             recorded under it: raise it again with `volume claim` and plan again",
            volume.generation(),
            boot.generation
        ));
    }
    if volume.generation() < boot.generation {
        return Err(format!(
            "the claim generation {} does not exceed the snapshot's {}: fence the previous owner \
             and raise it with `volume claim` before a restore",
            volume.generation(),
            boot.generation
        ));
    }
    Ok(boot)
}

/// Why a server must not start on `volume`, if a restore said so: a `forensic` volume is never
/// served.
pub fn serving_refused(volume: &Volume) -> Result<Option<String>, StorageError> {
    Ok(marked(volume)?
        .filter(|marker| marker.mode == Mode::Forensic)
        .map(|_| {
            "the volume was restored for forensics: it is never served; read it with the \
             offline tools"
                .to_owned()
        }))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use permguard_core::assurance::AssuranceProfile;

    use super::*;

    fn scratch(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "pg-host-restore-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("the scratch directory");
        dir
    }

    fn marker(mode: Mode) -> Marker {
        Marker {
            mode,
            at: 1_800_000_000,
            generation: 3,
            previous_boot_id: [7; 16],
            plan_id: [8; 16],
        }
    }

    /// WP-7.9: a marker round trips in every mode, and is closed: another version, a label more
    /// or an unknown mode is refused.
    #[test]
    fn a_marker_round_trips_and_is_closed() {
        for mode in [Mode::Dr, Mode::Forensic, Mode::Clone] {
            let held = marker(mode);
            assert_eq!(
                Marker::decode(&held.encode().expect("encodes")).expect("reads"),
                held
            );
            assert_eq!(Mode::parse(mode.as_str()), Some(mode));
        }
        assert_eq!(Mode::parse("warm"), None);
        let Value::Map(pairs) =
            cbor::decode_canonical(&marker(Mode::Dr).encode().expect("encodes")).expect("cbor")
        else {
            panic!("a map");
        };
        let encode =
            |pairs: Vec<(Value, Value)>| cbor::encode(&Value::Map(pairs)).expect("encodes");
        let mut extra = pairs.clone();
        extra.push((Value::Int(7), Value::Int(0)));
        assert!(Marker::decode(&encode(extra)).is_err());
        let mut other = pairs.clone();
        other[0].1 = Value::Int(2);
        assert!(Marker::decode(&encode(other)).is_err());
        let mut unknown = pairs;
        unknown[1].1 = Value::Text("warm".to_owned());
        assert!(Marker::decode(&encode(unknown)).is_err());
    }

    /// WP-7.9: the fence needs a claim generation above the snapshot's `BOOT`; a forensic marker
    /// refuses serving, another mode does not.
    #[test]
    fn the_fence_needs_a_raised_claim_and_forensic_is_never_served() {
        let root = scratch("fence");
        {
            let volume = Volume::claim(&root, AssuranceProfile::Development).expect("claimed");
            assert!(fence(&volume).is_err(), "no start recorded");
            let dir = volume
                .host()
                .subdir(crate::identity::DIRECTORY, true)
                .expect("the identity directory");
            write::replace_bytes(
                &dir,
                crate::identity::BOOT,
                &Boot {
                    boot_id: [9; 16],
                    generation: 0,
                }
                .encode()
                .expect("encodes"),
            )
            .expect("BOOT");
            let refused = fence(&volume).expect_err("the claim was not raised");
            assert!(refused.contains("does not exceed"), "{refused}");
        }
        crate::storage::volume::set_claim(&root, 1).expect("raised");
        let volume = Volume::claim(&root, AssuranceProfile::Development).expect("claimed");
        assert_eq!(fence(&volume).expect("fenced").boot_id, [9; 16]);

        assert_eq!(serving_refused(&volume).expect("reads"), None);
        mark(&volume, &marker(Mode::Dr)).expect("marked");
        assert_eq!(serving_refused(&volume).expect("reads"), None);
        assert_eq!(marked(&volume).expect("reads"), Some(marker(Mode::Dr)));
        mark(&volume, &marker(Mode::Forensic)).expect("marked");
        assert!(serving_refused(&volume).expect("reads").is_some());
    }

    /// WP-7.9: a run's marker is written through the mutation transaction, and the domain shows a
    /// run applied only when the marker records the plan the run names.
    #[test]
    fn a_run_is_recorded_and_shown_by_its_plan() {
        let root = scratch("record");
        let volume = Volume::claim(&root, AssuranceProfile::Development).expect("claimed");
        let mutations = Mutations::open_offline(&volume, "test").expect("the journal");
        let id = OperationId::from_bytes([1; 16]);
        let restores = Restores(&volume);
        assert_eq!(restores.observe(&id, Some(&run_target(&[8; 16]))), None);
        record(
            &mutations,
            &volume,
            &marker(Mode::Clone),
            Initiator::System("cli".to_owned()),
        )
        .expect("recorded");
        assert_eq!(marked(&volume).expect("reads"), Some(marker(Mode::Clone)));
        assert_eq!(
            restores.observe(&id, Some(&run_target(&[8; 16]))),
            Some(Observed {
                revision: 3,
                target: Some(run_target(&[8; 16])),
            })
        );
        assert_eq!(restores.observe(&id, Some(&run_target(&[9; 16]))), None);
        assert_eq!(restores.observe(&id, Some("restore-plan:clone")), None);
        assert_eq!(restores.observe(&id, None), None);
    }
}
