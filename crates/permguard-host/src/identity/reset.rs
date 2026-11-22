// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The identity reset (WP-4.1, owner decisions of 2026-10-09): a new `host_id` and chain, never
//! an in-place replacement. The memberships are settled first, by whoever calls; this module
//! retires the identity and provisions the next.
//!
//! | Step     | What                                                                                     |
//! | -------- | ---------------------------------------------------------------------------------------- |
//! | retire   | in this process at once: the identity signs nothing more                                 |
//! | evidence | the public records kept as the retired identity's, with the record of the reset          |
//! | marker   | the reset under way: an open refuses from here, a reset run again completes              |
//! | destroy  | every private key through its provider, then every key the store holds                   |
//! | new      | the provisioning record removed and a new identity provisioned; the marker cleared last  |
//!
//! The record of a reset is `{1 old host_id, 2 at, 3? operation id}`.
//!
//! The running process serves the new identity after a restart; a deployment pinning
//! `host.identity.witness` updates it then.

use std::sync::Arc;
use std::sync::atomic::Ordering;

use crate::keys::ring::Ring;

use permguard_objects::cbor::{self, Value};

use super::record::{self, Init};
use super::store::IdentityStore;
use super::{Identity, IdentityError, Suite, corrupt, slot};
use crate::keys::KeyProvider;
use crate::operations::journal::OperationId;
use crate::operations::mutation::{Applying, Observed};

pub use super::files::{RESET, RESETTING, RETIRED, marked, resume, resume_run};
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

    /// Whether an identity was ever retired where this one lives: this Host is one a reset
    /// provisioned.
    pub fn was_reset(&self) -> Result<bool, IdentityError> {
        Ok(!self.store.retired()?.is_empty())
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
        self.store.retire(
            applying,
            &old_host_id,
            &reset_record(&old_host_id, now, Some(&applying.operation_id()))?,
        )?;
        self.store.mark_resetting(applying, &old_host_id)?;
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
            self.store.as_ref(),
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

/// Completes an interrupted reset of the identity `store` keeps, at the home `volume_id`, as
/// `initiator`, one operation of the mutation engine: `None` when no reset is under way.
#[allow(clippy::too_many_arguments)]
pub fn resume_run_in(
    mutations: &crate::operations::mutation::Mutations,
    store: &dyn IdentityStore,
    volume_id: [u8; 16],
    provisioner: &Provisioner,
    rings: &[Arc<Ring>],
    suite: Suite,
    initiator: crate::operations::journal::Initiator,
    now: u64,
) -> Result<Option<Reset>, crate::operations::mutation::MutationError<IdentityError>> {
    use crate::operations::mutation::{Applied, Begin, Failure, MutationError, Outcome};
    let Some(marker) = store.resetting().map_err(MutationError::Refused)? else {
        return Ok(None);
    };
    // The reset that stopped left its operation open, and the engine takes no other while one
    // is: it is resolved first, against what the store holds of it, since no identity opens
    // while a reset is under way.
    mutations.recover(&Resetting(store)).map_err(|error| {
        MutationError::Unavailable(format!(
            "resolving the reset that stopped before it is completed: {error}"
        ))
    })?;
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
            let reset = resume_in(
                applying,
                store,
                volume_id,
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

/// The identity's domain while a reset is under way and no identity opens: what recovery asks
/// of the reset that stopped, before it is completed. That reset is done when the store keeps
/// the evidence of a retired identity under its operation and the identity provisioned is
/// another; it is not while the retired one, or none, still stands. No other operation of the
/// identity can be open here: the engine takes a reset only when none is.
pub struct Resetting<'a>(pub &'a dyn IdentityStore);

impl crate::operations::mutation::Domain for Resetting<'_> {
    fn name(&self) -> &'static str {
        super::DOMAIN
    }

    fn observe(
        &self,
        operation_id: &OperationId,
        target: Option<&str>,
    ) -> Result<Option<Observed>, String> {
        if !target.is_some_and(|target| target.starts_with("reset:")) {
            return Err(format!(
                "an operation of the identity that is not a reset, `{}`, is open while a reset \
                 is under way",
                target.unwrap_or("none")
            ));
        }
        let unread = |error: IdentityError| error.to_string();
        let standing = match self.0.init().map_err(unread)? {
            Some(bytes) => Some(record::uuid_text(
                &Init::decode(&bytes).map_err(|error| error.0)?.host_id,
            )),
            None => None,
        };
        Ok(reset_of(&self.0.retired().map_err(unread)?, operation_id)
            .filter(|_| standing.is_some())
            .filter(|retired| standing.as_deref() != Some(retired.as_str()))
            .and(standing)
            .map(|host_id| Observed {
                revision: 1,
                target: Some(format!("host:{host_id}")),
            }))
    }
}

/// The retired identity whose reset record names the operation `operation_id`.
fn reset_of(retired: &[super::store::Retired], operation_id: &OperationId) -> Option<String> {
    retired.iter().find_map(|retired| {
        // A record that is not a reset's names no operation.
        let Ok(Value::Map(pairs)) = cbor::decode_canonical(retired.reset.as_deref()?) else {
            return None;
        };
        pairs
            .iter()
            .any(|(key, value)| {
                *key == Value::Int(3) && *value == Value::Bytes(operation_id.as_bytes().to_vec())
            })
            .then(|| retired.host_id.clone())
    })
}

/// The identity the mark `marker` of a reset under way names.
pub(super) fn marked_host(marker: &[u8]) -> Result<[u8; 16], IdentityError> {
    <[u8; 16]>::try_from(marker).map_err(|_| corrupt("RESETTING does not name a host_id"))
}

/// The identity a reset under way retires, when one is: the start refuses until it is
/// completed.
pub fn marked_in(store: &dyn IdentityStore) -> Result<Option<[u8; 16]>, IdentityError> {
    store
        .resetting()?
        .map(|marker| marked_host(&marker))
        .transpose()
}

/// Completes the reset marked under way in `store`, at the home `volume_id`: what a reset run
/// again does after a crash. The mark must name a retired identity whose evidence is kept, and
/// the provisioning record, while there, that same identity; the old identity's keys are
/// destroyed through the provider made for it, the `rings` retired. Answers `None` when no reset
/// is under way.
#[allow(clippy::too_many_arguments)]
pub fn resume_in(
    applying: &Applying<'_>,
    store: &dyn IdentityStore,
    volume_id: [u8; 16],
    provisioner: &Provisioner,
    rings: &[Arc<Ring>],
    suite: Suite,
    now: u64,
    now_millis: u64,
) -> Result<Option<Reset>, IdentityError> {
    let Some(marker) = store.resetting()? else {
        return Ok(None);
    };
    let old_host_id = marked_host(&marker)?;
    let old = record::uuid_text(&old_host_id);
    let kept = store
        .retired()?
        .into_iter()
        .any(|retired| retired.host_id == old && retired.reset.is_some() && retired.init);
    if !kept {
        return Err(corrupt(
            "RESETTING names an identity whose evidence was not kept: nothing is completed",
        ));
    }
    if let Some(bytes) = store.init()? {
        let init = Init::decode(&bytes)?;
        if init.host_id != old_host_id {
            // The new identity was published and the marker not yet removed: the reset is
            // complete but for that.
            store.clear_resetting()?;
            return Ok(Some(Reset {
                old_host_id,
                host_id: init.host_id,
                witness: record::witness(&bytes, &volume_id, &init.fingerprint),
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
    complete(store, volume_id, provisioner, suite, now, now_millis).map(|reset| {
        Some(Reset {
            old_host_id,
            ..reset
        })
    })
}

/// Removes the provisioning record and provisions the new identity; the mark goes once the new
/// record is published.
fn complete(
    store: &dyn IdentityStore,
    volume_id: [u8; 16],
    provisioner: &Provisioner,
    suite: Suite,
    now: u64,
    now_millis: u64,
) -> Result<Reset, IdentityError> {
    store.remove_init()?;
    Identity::provision_records(
        store,
        volume_id,
        |host_id| provisioner(host_id),
        suite,
        now,
        now_millis,
    )?;
    let bytes = store
        .init()?
        .ok_or_else(|| corrupt("the new identity has no INIT"))?;
    let init = Init::decode(&bytes)?;
    Ok(Reset {
        old_host_id: [0; 16],
        host_id: init.host_id,
        witness: record::witness(&bytes, &volume_id, &init.fingerprint),
        fingerprint: init.fingerprint,
    })
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
///
/// No retired identity is an answer; a directory or a record that does not read stops the
/// recovery, since the reset it could not show may be the one asked about.
pub(super) fn observe(
    identity: &Identity,
    operation_id: &OperationId,
) -> Result<Option<Observed>, String> {
    let retired = identity
        .store
        .retired()
        .map_err(|error| error.to_string())?;
    Ok(reset_of(&retired, operation_id)
        .filter(|retired| *retired != identity.host_id_text())
        .map(|_| Observed {
            revision: 1,
            target: Some(format!("host:{}", identity.host_id_text())),
        }))
}

#[cfg(test)]
mod tests;
