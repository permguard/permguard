// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The application-consistent snapshot on the Host API (WP-7.8, `6-contracts/8-contract-host-api.md`
//! lifecycle, configuration and operations).
//!
//! | Route                               | Grant           | Request                  | Answer                                   |
//! | ----------------------------------- | --------------- | ------------------------ | ---------------------------------------- |
//! | `POST /host/v1/backup/prepare`      | `backup.manage` | `{}`                     | the signed manifest, the token, receipt  |
//! | `POST /host/v1/backup/finalize`     | `backup.manage` | `{token, snapshot_id}`   | its receipt and the snapshot id          |
//! | `POST /host/v1/backup/abort`        | `backup.manage` | `{token}`                | its receipt                              |
//! | `GET /host/v1/backups`              | `backup.read`   |                          | the backups this Host knows              |
//!
//! The Host owns only the barrier: the storage driver takes the snapshot between the prepare and
//! the finalize, bound to the token. A prepare nobody ends aborts when its barrier expires.

use std::sync::Arc;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::{Deserialize, Serialize};

use permguard_core::authz::{Actor, operations};
use permguard_core::{ErrorClass, codes};

use super::grants::rfc3339;
use super::{HostApi, Receipt, Refusal};
use crate::keys::ring::HOST_OPERATIONS;
use crate::operations::backup::{self, Backups, Refused, Signing};
use crate::operations::journal::Initiator;

/// `POST /host/v1/backup/prepare`: nothing but the call.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrepareBackup {}

/// What a prepare answers.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackupPrepared {
    /// The backup: the prepare's operation.
    pub operation_id: String,
    /// The COSE_Sign1 `permguard.snapshot.manifest.v1`, base64url.
    pub manifest: String,
    /// The snapshot token, base64url: answered here once, presented to finalize or abort.
    pub token: String,
    /// When the barrier aborts by itself, RFC 3339.
    pub expires_at: String,
    pub receipt: Receipt,
}

/// `POST /host/v1/backup/finalize`.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FinalizeBackup {
    pub token: String,
    /// The storage driver's id of the snapshot it took.
    pub snapshot_id: String,
}

/// `POST /host/v1/backup/abort`.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AbortBackup {
    pub token: String,
}

// The token is a secret: none of these prints it in a `Debug`.
impl std::fmt::Debug for BackupPrepared {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BackupPrepared")
            .field("operation_id", &self.operation_id)
            .field("expires_at", &self.expires_at)
            .field("receipt", &self.receipt)
            .finish_non_exhaustive()
    }
}

impl std::fmt::Debug for FinalizeBackup {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FinalizeBackup")
            .field("snapshot_id", &self.snapshot_id)
            .finish_non_exhaustive()
    }
}

impl std::fmt::Debug for AbortBackup {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AbortBackup").finish_non_exhaustive()
    }
}

/// What a finalize or an abort answers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackupEnded {
    /// The backup it ended.
    pub backup: String,
    /// `finalized` or `aborted`.
    pub state: String,
    /// The snapshot it bound, when finalized.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub snapshot_id: Option<String>,
    pub receipt: Receipt,
}

/// One backup this Host knows.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackupView {
    pub operation_id: String,
    /// When it was prepared, RFC 3339.
    pub at: String,
    /// `prepared`, `finalized` or `aborted`.
    pub state: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub snapshot_id: Option<String>,
    /// When it was finalized or aborted, RFC 3339.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ended_at: Option<String>,
    /// Its signed manifest, COSE_Sign1 `permguard.snapshot.manifest.v1` in base64url.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub manifest: Option<String>,
}

/// `GET /host/v1/backups`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackupList {
    /// Newest first.
    pub backups: Vec<BackupView>,
}

fn unavailable(detail: impl Into<String>) -> Refusal {
    Refusal::new(ErrorClass::Unavailable, codes::common::UNAVAILABLE, detail)
}

fn refusal_of(refused: Refused) -> Refusal {
    match refused {
        Refused::Busy => Refusal::new(
            ErrorClass::Conflict,
            codes::common::CONFLICT,
            refused.to_string(),
        ),
        Refused::Unknown => Refusal::new(
            ErrorClass::NotFound,
            codes::common::NOT_FOUND,
            refused.to_string(),
        ),
        Refused::InvalidSnapshotId(_) => Refusal::new(
            ErrorClass::Validation,
            codes::common::INVALID_ARGUMENT,
            refused.to_string(),
        ),
        Refused::Unavailable(detail) => unavailable(detail),
    }
}

impl HostApi {
    /// The backups and the transaction they run through, or `unavailable` without either.
    fn backups(
        &self,
    ) -> Result<(&Arc<Backups>, &Arc<crate::operations::mutation::Mutations>), Refusal> {
        match (&self.backups, &self.mutations) {
            (Some(backups), Some(mutations)) => Ok((backups, mutations)),
            _ => Err(unavailable(
                "this Host keeps no backups: it runs without a volume",
            )),
        }
    }

    /// `POST /host/v1/backup/prepare` under `backup.manage` (WP-7.8): raises the barrier, signs
    /// the manifest and answers the token once. A timer aborts the backup when its barrier
    /// expires.
    pub fn prepare_backup(
        &self,
        actor: &Actor,
        _request: PrepareBackup,
    ) -> Result<BackupPrepared, Refusal> {
        let admitted = self.admit(actor, operations::BACKUP_MANAGE)?;
        let (backups, mutations) = self.backups()?;
        let now = self.time.now_secs();
        backups.expire(mutations, now);
        let ring = self.keys.ring(HOST_OPERATIONS).ok_or_else(|| {
            unavailable(format!(
                "a snapshot manifest is signed under `{HOST_OPERATIONS}`, which this Host does \
                 not keep"
            ))
        })?;
        let identity = self
            .identity
            .as_ref()
            .ok_or_else(|| unavailable("no Host identity is open on this process"))?;
        let prepared = backups
            .prepare(
                mutations,
                Initiator::Principal(admitted.principal.to_string()),
                &Signing {
                    ring,
                    host_id: identity.host_id(),
                    recovery_key_id: self.backup_labels.0.clone(),
                    encryption_profile: self.backup_labels.1.clone(),
                },
                now,
            )
            .map_err(refusal_of)?;
        // The barrier ends by itself: an operator who never finalizes holds nothing for long.
        let time = Arc::clone(&self.time);
        if let Err(error) = backups.watch(Arc::clone(mutations), Arc::new(move || time.now_secs()))
        {
            // Every later backup call and every mutation past the deadline still sees it expire.
            tracing::warn!(
                event.name = "host.backup_timer_failed",
                component = "host",
                error = %error,
                "the barrier's timer did not start: it expires at the next backup call"
            );
        }
        Ok(BackupPrepared {
            operation_id: prepared.operation_id.to_string(),
            manifest: URL_SAFE_NO_PAD.encode(&prepared.manifest),
            token: prepared.token,
            expires_at: rfc3339(prepared.expires_at),
            receipt: self.receipt(prepared.operation_id, prepared.revision),
        })
    }

    /// `POST /host/v1/backup/finalize` under `backup.manage` (WP-7.8): binds the snapshot id to
    /// the backup the token names, records it and lowers the barrier.
    pub fn finalize_backup(
        &self,
        actor: &Actor,
        request: FinalizeBackup,
    ) -> Result<BackupEnded, Refusal> {
        let admitted = self.admit(actor, operations::BACKUP_MANAGE)?;
        let (backups, mutations) = self.backups()?;
        let now = self.time.now_secs();
        backups.expire(mutations, now);
        let backup = backups
            .finalize(
                mutations,
                Initiator::Principal(admitted.principal.to_string()),
                &request.token,
                &request.snapshot_id,
                now,
            )
            .map_err(refusal_of)?;
        Ok(BackupEnded {
            backup: backup.backup.to_string(),
            state: backup::FINALIZED.to_owned(),
            snapshot_id: Some(request.snapshot_id),
            receipt: self.receipt(backup.operation_id, backup.revision),
        })
    }

    /// `POST /host/v1/backup/abort` under `backup.manage` (WP-7.8): ends the backup the token
    /// names and lowers the barrier.
    pub fn abort_backup(
        &self,
        actor: &Actor,
        request: AbortBackup,
    ) -> Result<BackupEnded, Refusal> {
        let admitted = self.admit(actor, operations::BACKUP_MANAGE)?;
        let (backups, mutations) = self.backups()?;
        let now = self.time.now_secs();
        backups.expire(mutations, now);
        let backup = backups
            .abort(
                mutations,
                Initiator::Principal(admitted.principal.to_string()),
                &request.token,
                now,
            )
            .map_err(refusal_of)?;
        Ok(BackupEnded {
            backup: backup.backup.to_string(),
            state: backup::ABORTED.to_owned(),
            snapshot_id: None,
            receipt: self.receipt(backup.operation_id, backup.revision),
        })
    }

    /// `GET /host/v1/backups` under `backup.read` (WP-7.8): every backup this Host knows, newest
    /// first.
    pub fn list_backups(&self, actor: &Actor) -> Result<BackupList, Refusal> {
        let _admitted = self.admit(actor, operations::BACKUP_READ)?;
        let (backups, mutations) = self.backups()?;
        backups.expire(mutations, self.time.now_secs());
        Ok(BackupList {
            backups: backups
                .list()
                .map_err(unavailable)?
                .into_iter()
                .map(|listed| BackupView {
                    operation_id: listed.operation_id,
                    at: rfc3339(listed.at),
                    state: listed.state,
                    snapshot_id: listed.snapshot_id,
                    ended_at: listed.ended_at.map(rfc3339),
                    manifest: listed
                        .manifest
                        .map(|manifest| URL_SAFE_NO_PAD.encode(manifest)),
                })
                .collect(),
        })
    }
}

#[cfg(test)]
mod tests;
