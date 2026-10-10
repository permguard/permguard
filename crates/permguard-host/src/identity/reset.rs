// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The identity reset (WP-4.1, owner decisions of 2026-10-09): a new `host_id` and chain, never
//! an in-place replacement. The memberships are settled first, by whoever calls; this module
//! retires the identity and provisions the next.
//!
//! ```text
//! host/identity/
//! ├── RESETTING                    the old host_id, while a reset is under way
//! └── retired/<old host_id>/
//!     ├── INIT, identity.cose, succession.cborseq, <epoch>.pub
//!     └── RESET                    {1 old host_id, 2 at, 3? operation id}
//! ```
//!
//! | Step     | What                                                                                     |
//! | -------- | ---------------------------------------------------------------------------------------- |
//! | retire   | in this process at once: the identity signs nothing more                                 |
//! | evidence | the public records copied under `retired/`, the `RESET` record written                   |
//! | marker   | `RESETTING`: an open refuses from here, a reset run again completes                      |
//! | destroy  | every private key through its provider, then every file of `keys/`                       |
//! | new      | `INIT` removed and a new identity provisioned in its place; the marker removed last      |
//!
//! The running process serves the new identity after a restart; a deployment pinning
//! `host.identity.witness` updates it then.

use std::sync::Arc;
use std::sync::atomic::Ordering;

use crate::keys::ring::Ring;

use permguard_objects::cbor::{self, Value};

use super::record::{self, Init};
use super::{
    DOCUMENT, INIT, Identity, IdentityError, KEYS, SUCCESSION, Suite, corrupt, directories, slot,
};
use crate::keys::KeyProvider;
use crate::operations::journal::OperationId;
use crate::operations::mutation::{Applying, Observed};
use crate::storage::volume::Volume;
use crate::storage::{Dir, tombstone, write};

/// The marker of a reset under way, beside `INIT`.
pub const RESETTING: &str = "RESETTING";
/// The directory of the retired identities, below `host/identity/`.
pub const RETIRED: &str = "retired";
/// The record of a reset, in its retired identity's directory.
pub const RESET: &str = "RESET";
/// The operation of the mutation engine.
pub const RESET_PLAN: &str = "identity.reset.plan";
pub const RESET_RUN: &str = "identity.reset.run";
/// The audit actions.
pub const AUDIT_RESET_PLANNED: &str = "host.identity.reset_planned";
pub const AUDIT_RESET: &str = "host.identity.reset";

/// Makes the provider of the identity a reset provisions, for the `host_id` just minted: a
/// sealing provider binds every key to its Host (WP-3.2).
pub type Provisioner =
    Arc<dyn Fn(&[u8; 16]) -> Result<Arc<dyn KeyProvider>, IdentityError> + Send + Sync>;

/// What a reset produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reset {
    pub old_host_id: [u8; 16],
    pub host_id: [u8; 16],
    /// The new identity's first fingerprint: its pin.
    pub fingerprint: String,
    /// The new identity's external witness, for `host.identity.witness`.
    pub witness: String,
}

impl Identity {
    /// Hands the identity what makes the provider of the identity a reset provisions.
    #[must_use]
    pub fn with_provisioner(mut self, provisioner: Provisioner) -> Self {
        self.provisioner = Some(provisioner);
        self
    }

    /// Whether this process can provision the identity a reset makes.
    pub fn can_reset(&self) -> bool {
        self.provisioner.is_some()
    }

    /// Whether a reset retired the identity.
    pub fn is_retired(&self) -> bool {
        self.retired.load(Ordering::SeqCst)
    }

    /// Resets the identity inside the operation `applying` names: retired here, its public
    /// evidence kept, its private keys destroyed, a new identity of `suite` provisioned on the
    /// volume. Refused without a provisioner; a failure past the marker leaves a reset that
    /// running it again completes.
    pub fn reset(
        &self,
        applying: &Applying<'_>,
        rings: &[Arc<Ring>],
        suite: Suite,
        now: u64,
        now_millis: u64,
    ) -> Result<Reset, IdentityError> {
        let provisioner = self.provisioner.clone().ok_or_else(|| {
            IdentityError::Refused(
                "this process cannot provision an identity: no provisioner is composed".to_owned(),
            )
        })?;
        // One reset at a time, and one per identity: taken before anything is written.
        if self
            .resetting
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
            || self.is_retired()
        {
            return Err(IdentityError::Retired);
        }
        let outcome = self.reset_once(applying, rings, &provisioner, suite, now, now_millis);
        if outcome.is_err() && !self.is_retired() {
            // Nothing was retired: a later run may try again.
            self.resetting.store(false, Ordering::SeqCst);
        }
        outcome
    }

    fn reset_once(
        &self,
        applying: &Applying<'_>,
        rings: &[Arc<Ring>],
        provisioner: &Provisioner,
        suite: Suite,
        now: u64,
        now_millis: u64,
    ) -> Result<Reset, IdentityError> {
        let old_host_id = self.host_id();
        let retired = self
            .dir
            .subdir(RETIRED, true)?
            .subdir(&record::uuid_text(&old_host_id), true)?;
        keep_evidence(&self.dir, &self.keys, &retired)?;
        write::replace_bytes(
            &retired,
            RESET,
            &reset_record(&old_host_id, now, Some(&applying.operation_id()))?,
        )?;
        write::replace_bytes(&self.dir, RESETTING, &old_host_id)?;
        // Retired once the marker is durable, and once only: a second reset of this identity,
        // however concurrent, is refused here.
        if self
            .retired
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            return Err(IdentityError::Retired);
        }
        retire_rings(applying, rings, &old_host_id)?;
        // Every private key this identity held, through the provider that holds it; a key the
        // provider could not destroy is reported and its file goes all the same.
        for epoch in 1..=self.epoch() {
            if let Err(error) = self.provider.destroy(&slot(epoch)) {
                tracing::warn!(
                    event.name = "host.identity_key_kept",
                    component = "host",
                    epoch,
                    error = %error,
                    "a reset identity key could not be destroyed"
                );
            }
        }
        complete(
            &self.dir,
            &self.keys,
            self.volume_id,
            provisioner,
            suite,
            now,
            now_millis,
        )
        .map(|reset| Reset {
            old_host_id,
            ..reset
        })
    }
}

/// Resets `identity` as `initiator`, with no request id: the offline CLI's emergency reset, its
/// memberships settled first.
pub fn run(
    mutations: &crate::operations::mutation::Mutations,
    identity: &Identity,
    rings: &[Arc<Ring>],
    initiator: crate::operations::journal::Initiator,
    now: u64,
) -> Result<Reset, crate::operations::mutation::MutationError<IdentityError>> {
    use crate::operations::mutation::{Applied, Begin, Failure, MutationError, Outcome};
    let suite = identity.suite();
    let mut produced = None;
    let outcome = mutations.run(
        Begin {
            domain: super::DOMAIN,
            operation: RESET_RUN,
            action: AUDIT_RESET,
            initiator,
            request: None,
            target: Some(format!("reset:{}", identity.host_id_text())),
        },
        |applying| {
            let reset = identity
                .reset(applying, rings, suite, now, now.saturating_mul(1000))
                .map_err(|error| match error {
                    IdentityError::Refused(_) => Failure::Refused(error),
                    other => Failure::Indeterminate(other),
                })?;
            let applied = Applied {
                revision: 1,
                target: Some(format!("host:{}", record::uuid_text(&reset.host_id))),
                value: (),
            };
            produced = Some(reset);
            Ok(applied)
        },
    )?;
    match (outcome, produced) {
        (Outcome::Applied(()), Some(reset)) => Ok(reset),
        _ => Err(MutationError::Unrecorded(
            "a reset with no request id answered without applying".to_owned(),
        )),
    }
}

/// Retires the key rings with the identity (owner decision of 2026-10-10).
fn retire_rings(
    applying: &Applying<'_>,
    rings: &[Arc<Ring>],
    old_host_id: &[u8; 16],
) -> Result<(), IdentityError> {
    for ring in rings {
        ring.retire(applying, old_host_id)
            .map_err(|error| corrupt(format!("retiring the ring `{}`: {error}", ring.id())))?;
    }
    Ok(())
}

/// Completes an interrupted reset as `initiator`, one operation of the mutation engine (the
/// offline CLI): `None` when no reset is under way.
pub fn resume_run(
    mutations: &crate::operations::mutation::Mutations,
    volume: &Volume,
    provisioner: &Provisioner,
    rings: &[Arc<Ring>],
    suite: Suite,
    initiator: crate::operations::journal::Initiator,
    now: u64,
) -> Result<Option<Reset>, crate::operations::mutation::MutationError<IdentityError>> {
    use crate::operations::mutation::{Applied, Begin, Failure, MutationError, Outcome};
    let Some(marker) = directories(volume)
        .map_err(IdentityError::from)
        .and_then(|(dir, _)| Ok(dir.read(RESETTING)?))
        .map_err(MutationError::Refused)?
    else {
        return Ok(None);
    };
    let target = <[u8; 16]>::try_from(marker.as_slice())
        .map(|old| format!("reset:{}", record::uuid_text(&old)))
        .unwrap_or_else(|_| "reset:unknown".to_owned());
    let mut produced = None;
    let outcome = mutations.run(
        Begin {
            domain: super::DOMAIN,
            operation: RESET_RUN,
            action: AUDIT_RESET,
            initiator,
            request: None,
            target: Some(target),
        },
        |applying| {
            let reset = resume(
                applying,
                volume,
                provisioner,
                rings,
                suite,
                now,
                now.saturating_mul(1000),
            )
            .map_err(|error| match error {
                IdentityError::Corrupt(_) | IdentityError::Refused(_) => Failure::Refused(error),
                other => Failure::Indeterminate(other),
            })?
            .ok_or_else(|| Failure::Refused(corrupt("the reset was completed meanwhile")))?;
            let applied = Applied {
                revision: 1,
                target: Some(format!("host:{}", record::uuid_text(&reset.host_id))),
                value: (),
            };
            produced = Some(reset);
            Ok(applied)
        },
    )?;
    match (outcome, produced) {
        (Outcome::Applied(()), Some(reset)) => Ok(Some(reset)),
        _ => Err(MutationError::Unrecorded(
            "a resumed reset answered without applying".to_owned(),
        )),
    }
}

/// The identity a reset under way on `volume` retires, when one is: the start refuses until it
/// is completed.
pub fn marked(volume: &Volume) -> Result<Option<[u8; 16]>, IdentityError> {
    directories(volume)?
        .0
        .read(RESETTING)?
        .map(|marker| {
            <[u8; 16]>::try_from(marker.as_slice())
                .map_err(|_| corrupt("RESETTING does not name a host_id"))
        })
        .transpose()
}

/// Completes the reset `RESETTING` marks on `volume`: what a reset run again does after a crash
/// (the offline CLI). The marker must name a retired identity whose evidence is kept, and `INIT`,
/// while there, that same identity; the old identity's keys are destroyed through the provider
/// made for it, the `rings` retired. Answers `None` when no reset is under way.
pub fn resume(
    applying: &Applying<'_>,
    volume: &Volume,
    provisioner: &Provisioner,
    rings: &[Arc<Ring>],
    suite: Suite,
    now: u64,
    now_millis: u64,
) -> Result<Option<Reset>, IdentityError> {
    let (dir, keys) = directories(volume)?;
    let Some(marker) = dir.read(RESETTING)? else {
        return Ok(None);
    };
    let old_host_id: [u8; 16] = marker
        .as_slice()
        .try_into()
        .map_err(|_| corrupt("RESETTING does not name a host_id"))?;
    let evidence = dir
        .subdir(RETIRED, true)?
        .subdir(&record::uuid_text(&old_host_id), true)?;
    if evidence.read(RESET)?.is_none() || evidence.read(INIT)?.is_none() {
        return Err(corrupt(
            "RESETTING names an identity whose evidence was not kept: nothing is completed",
        ));
    }
    if let Some(bytes) = dir.read(INIT)? {
        let init = Init::decode(&bytes)?;
        if init.host_id != old_host_id {
            // The new identity was published and the marker not yet removed: the reset is
            // complete but for that.
            tombstone::delete(&dir, RESETTING)?;
            return Ok(Some(Reset {
                old_host_id,
                host_id: init.host_id,
                witness: record::witness(&bytes, &volume.id(), &init.fingerprint),
                fingerprint: init.fingerprint,
            }));
        }
    }
    retire_rings(applying, rings, &old_host_id)?;
    // The old identity's keys, through the provider made for it.
    let old = provisioner(&old_host_id)?;
    for slot in old.slots()? {
        if let Err(error) = old.destroy(&slot) {
            tracing::warn!(
                event.name = "host.identity_key_kept",
                component = "host",
                error = %error,
                "a reset identity key could not be destroyed"
            );
        }
    }
    complete(
        &dir,
        &keys,
        volume.id(),
        provisioner,
        suite,
        now,
        now_millis,
    )
    .map(|reset| {
        Some(Reset {
            old_host_id,
            ..reset
        })
    })
}

/// Removes `INIT` and provisions the new identity; the marker goes once `INIT` is published.
fn complete(
    dir: &Dir,
    keys: &Dir,
    volume_id: [u8; 16],
    provisioner: &Provisioner,
    suite: Suite,
    now: u64,
    now_millis: u64,
) -> Result<Reset, IdentityError> {
    if dir.read(INIT)?.is_some() {
        tombstone::delete(dir, INIT)?;
    }
    Identity::provision_in(
        dir,
        keys,
        volume_id,
        |host_id| provisioner(host_id),
        suite,
        now,
        now_millis,
    )?;
    let bytes = dir
        .read(INIT)?
        .ok_or_else(|| corrupt("the new identity has no INIT"))?;
    let init = Init::decode(&bytes)?;
    Ok(Reset {
        old_host_id: [0; 16],
        host_id: init.host_id,
        witness: record::witness(&bytes, &volume_id, &init.fingerprint),
        fingerprint: init.fingerprint,
    })
}

/// Copies the public records of the identity into `retired`: `INIT`, the document, the
/// successions and every public key. Nothing private is kept.
fn keep_evidence(dir: &Dir, keys: &Dir, retired: &Dir) -> Result<(), IdentityError> {
    for name in [INIT, DOCUMENT, SUCCESSION] {
        if let Some(bytes) = dir.read(name)? {
            write::replace_bytes(retired, name, &bytes)?;
        }
    }
    for name in keys.names()? {
        if name.ends_with(".pub")
            && let Some(bytes) = keys.read(&name)?
        {
            write::replace_bytes(retired, &format!("{KEYS}-{name}"), &bytes)?;
        }
    }
    Ok(())
}

fn reset_record(
    old_host_id: &[u8; 16],
    at: u64,
    operation_id: Option<&OperationId>,
) -> Result<Vec<u8>, IdentityError> {
    let mut pairs = vec![
        (Value::Int(1), Value::Bytes(old_host_id.to_vec())),
        (
            Value::Int(2),
            Value::Int(i64::try_from(at).unwrap_or(i64::MAX)),
        ),
    ];
    if let Some(operation_id) = operation_id {
        pairs.push((
            Value::Int(3),
            Value::Bytes(operation_id.as_bytes().to_vec()),
        ));
    }
    cbor::encode(&Value::Map(pairs)).map_err(|error| corrupt(format!("{error:?}")))
}

/// The reset the operation `operation_id` made, as recovery sees it from the identity it left:
/// a retired identity whose `RESET` names the operation, the open identity another Host.
pub(super) fn observe(identity: &Identity, operation_id: &OperationId) -> Option<Observed> {
    let retired = identity.dir.subdir(RETIRED, false).ok()?;
    for name in retired.subdirs().ok()? {
        let Some(bytes) = retired
            .subdir(&name, false)
            .ok()
            .and_then(|dir| dir.read(RESET).ok().flatten())
        else {
            continue;
        };
        let Ok(Value::Map(pairs)) = cbor::decode_canonical(&bytes) else {
            continue;
        };
        let named = pairs.iter().any(|(key, value)| {
            *key == Value::Int(3) && *value == Value::Bytes(operation_id.as_bytes().to_vec())
        });
        if named && name != identity.host_id_text() {
            return Some(Observed {
                revision: 1,
                target: Some(format!("host:{}", identity.host_id_text())),
            });
        }
    }
    None
}

#[cfg(test)]
mod tests;
