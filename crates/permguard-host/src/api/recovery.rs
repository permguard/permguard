// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! `GET /host/v1/recovery` and `POST /host/v1/recovery/acknowledge` (WP-8.2, `7-contracts/8`
//! Recovery): the recovery started offline, and its acknowledgement, under `authz.admin`.

use permguard_core::authz::{Actor, operations};
use permguard_core::{AuditEvent, ErrorClass, Subject, codes};
use serde::{Deserialize, Serialize};

use super::{HostApi, Refusal};

/// The recovery waiting to be acknowledged, or none.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveryView {
    /// Whether a recovery waits.
    pub waiting: bool,
    /// When it was started, RFC 3339.
    pub started_at: Option<String>,
    /// Why, as the operator wrote it.
    pub reason: Option<String>,
}

/// What an acknowledgement answers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveryAcknowledged {
    /// Whether a recovery was waiting, and is now acknowledged.
    pub acknowledged: bool,
    pub started_at: Option<String>,
    pub reason: Option<String>,
}

fn rfc3339(seconds: u64) -> String {
    permguard_core::time::to_rfc3339(i64::try_from(seconds).unwrap_or(i64::MAX))
}

fn unavailable(detail: impl std::fmt::Display) -> Refusal {
    Refusal::Api(
        permguard_core::ApiError::new(
            ErrorClass::Unavailable,
            codes::common::UNAVAILABLE,
            "the setup folder cannot be read",
        )
        .with_internal(detail.to_string()),
    )
}

impl HostApi {
    fn setup_folder(&self) -> Result<&crate::setup::Setup, Refusal> {
        self.setup.as_deref().ok_or_else(|| {
            Refusal::new(
                ErrorClass::Unavailable,
                codes::common::UNAVAILABLE,
                "this process composes no setup folder",
            )
        })
    }

    /// The recovery waiting to be acknowledged.
    pub fn recovery(&self, actor: &Actor) -> Result<RecoveryView, Refusal> {
        let _admitted = self.admit(actor, operations::AUTHZ_ADMIN)?;
        let held = self.setup_folder()?.recovery().map_err(unavailable)?;
        Ok(RecoveryView {
            waiting: held.is_some(),
            started_at: held.as_ref().map(|record| rfc3339(record.started_at)),
            reason: held.map(|record| record.reason),
        })
    }

    /// Acknowledges the recovery: the Host leaves `degraded: recovery`, and the trail records who.
    pub fn acknowledge_recovery(&self, actor: &Actor) -> Result<RecoveryAcknowledged, Refusal> {
        let admitted = self.admit(actor, operations::AUTHZ_ADMIN)?;
        let setup = self.setup_folder()?;
        let held = setup.recovery().map_err(unavailable)?;
        // The administrator a recovery made does not acknowledge it alone: another one, when there
        // is one, has to see it.
        if let Some(made) = held.as_ref().and_then(|record| record.made.as_deref())
            && made == admitted.principal.as_str()
            && let Some(store) = self.store.as_ref()
            && crate::setup::administered_by_another(store, made, self.time.now_secs())
        {
            return Err(Refusal::new(
                ErrorClass::Validation,
                codes::common::INVALID_ARGUMENT,
                "the administrator this recovery made does not acknowledge it: another administrator does",
            ));
        }
        if let Some(record) = &held {
            // Recorded first: a recovery acknowledged without a record would leave no trace.
            if let Some(audit) = self.audit.as_ref() {
                let target = format!("started_at={}", rfc3339(record.started_at));
                let event = AuditEvent::new(
                    crate::setup::AUDIT_RECOVERY_ACKNOWLEDGED,
                    Subject::Principal(admitted.principal.as_str()),
                )
                .on(&target);
                audit.append(&event, None).map_err(unavailable)?;
            }
            setup.acknowledge().map_err(unavailable)?;
            self.health.lifecycle().restore(
                permguard_core::lifecycle::HOST,
                crate::setup::RECOVERY_CAPABILITY,
            );
            tracing::info!(
                event.name = "host.recovery_acknowledged",
                component = "host",
                "an administrator acknowledged the recovery"
            );
        }
        Ok(RecoveryAcknowledged {
            acknowledged: held.is_some(),
            started_at: held.as_ref().map(|record| rfc3339(record.started_at)),
            reason: held.map(|record| record.reason),
        })
    }
}
