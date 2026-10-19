// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The member's `events.import` pass (WP-6.2c2a, owner decisions of 2026-10-18 and 2026-10-19).
//!
//! ```text
//! per active membership with an `events.import` task, per configured ledger its selector covers
//!   ─▶ open a task session over the ledger (the member opens every session)
//!   ─▶ `origins`: verify the checkpoint under the pinned `control.attest`, bound to this session,
//!      and each origin's manifest under the pinned `host.operations`
//!   ─▶ keep the checkpoint, the instant it verified and the revision: what freshness counts from
//!   ─▶ per origin other than this Host, per run the checkpoint names, each batch past what the
//!      consumer holds, ingested into the origin's own run under its membership, epoch and pins
//!   ─▶ a sequence the coordinator no longer holds, a batch that does not verify or forks: a
//!      durable gap, and the run is not advanced past it
//! ```
//!
//! Imported records keep their origin's bytes, signer, host, run and sequence; this Host signs
//! none of them and ships none of them: they live in its consumer, never in its producer.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use permguard_core::authz::Resource;

use super::{Member, MemberTask};
use crate::composition::{ImportOrigin, Imported, StreamImport};
use crate::identity::record::uuid_text;
use crate::membership::MembershipError;
use crate::membership::import::{
    FORK, Gap, MAX_GAPS, Origins, RETENTION, Request, State, UNVERIFIABLE, verify_origins,
};
use crate::membership::record::{Role, Status, TaskType};
use crate::operations::journal::Initiator;

/// The most batches one pass imports of one ledger: a member far behind catches up over several
/// passes.
pub const MAX_BATCHES_PER_PASS: usize = 256;

/// What a request is numbered by: the coordinator's replay window answers a request id it saw
/// with the answer it gave, so each is asked once, the boot id naming the incarnation.
static REQUEST_SEQ: AtomicU64 = AtomicU64::new(0);

/// What the member side imports with: its consumer of the event stream, and the ledgers the
/// configuration names.
pub struct Importing {
    pub engine: Arc<dyn StreamImport>,
    pub ledgers: Vec<Resource>,
}

fn request_id(boot: &[u8; 16], what: &str, at: u64) -> String {
    format!(
        "import-{}-{what}-{at}-{}",
        hex(boot),
        REQUEST_SEQ.fetch_add(1, Ordering::SeqCst) + 1
    )
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

impl Member<'_> {
    /// Imports what this Host's `events.import` tasks have due: the batches ingested, over every
    /// membership and ledger. A ledger that fails is logged; the next pass tries again.
    ///
    /// One caller at a time: the server's periodic pass. A ledger two memberships' import tasks
    /// cover is imported by neither, said each pass (after the review): its state, one per
    /// ledger, names one coordinator's origins.
    pub async fn import_due(&self, initiator: Initiator, importing: &Importing) -> usize {
        let mut imported = 0;
        let covering = |ledger: &Resource| {
            self.store
                .memberships()
                .into_iter()
                .filter(|(_, held)| held.role == Role::Member && held.status == Status::Active)
                .filter(|(_, held)| {
                    held.manifest.as_ref().is_some_and(|(manifest, ..)| {
                        manifest.selector.contains(ledger)
                            && manifest.tasks.iter().any(|task| {
                                task.task_type == TaskType::EventsImport
                                    && task.selector.contains(ledger)
                            })
                    })
                })
                .count()
        };
        for (id, held) in self.store.memberships() {
            if held.role != Role::Member || held.status != Status::Active {
                continue;
            }
            let Some((manifest, ..)) = &held.manifest else {
                continue;
            };
            for task in manifest
                .tasks
                .iter()
                .filter(|task| task.task_type == TaskType::EventsImport)
            {
                for ledger in importing.ledgers.iter().filter(|ledger| {
                    manifest.selector.contains(ledger) && task.selector.contains(ledger)
                }) {
                    if covering(ledger) > 1 {
                        tracing::warn!(
                            event.name = "host.membership.import_ambiguous",
                            component = "host",
                            resource = %ledger,
                            "more than one membership imports this ledger: it is imported by none"
                        );
                        continue;
                    }
                    match self
                        .import_ledger(&initiator, &id, &task.task_id, ledger, importing)
                        .await
                    {
                        Ok(count) => imported += count,
                        Err(error) => tracing::warn!(
                            event.name = "host.membership.import_failed",
                            component = "host",
                            membership_id = %uuid_text(&id),
                            task = %task.task_id,
                            resource = %ledger,
                            error = %error,
                            "a ledger could not be imported: the next pass tries again"
                        ),
                    }
                }
            }
        }
        imported
    }

    /// One session over `ledger`: the origins and their checkpoint, then their batches.
    async fn import_ledger(
        &self,
        initiator: &Initiator,
        id: &[u8; 16],
        task_id: &str,
        ledger: &Resource,
        importing: &Importing,
    ) -> Result<usize, MembershipError> {
        let storage = MembershipError::Storage;
        // A ledger holding every gap it may keep is not imported further.
        if importing
            .engine
            .import_state(ledger)
            .map_err(storage)?
            .is_some_and(|state| state.gaps.len() >= MAX_GAPS)
        {
            tracing::warn!(
                event.name = "host.membership.import_gaps_full",
                component = "host",
                resource = %ledger,
                "a ledger holds every gap its import may keep: it is not imported further"
            );
            return Ok(0);
        }
        let boot = self.identity.boot_id();
        let mut session = self
            .open_task(
                initiator.clone(),
                id,
                task_id,
                &ledger.to_string(),
                Vec::new(),
            )
            .await?;
        let now = self.time.now_secs();
        let answer = session
            .send(
                &request_id(&boot, "origins", now),
                Request::Origins.encode()?,
            )
            .await?;
        let origins = Origins::decode(&answer)?;
        // The manifest the lease was issued under: opening may have synced a re-pin.
        let manifest = self
            .store
            .membership(id)
            .and_then(|held| held.manifest.map(|(manifest, ..)| manifest))
            .ok_or_else(|| MembershipError::Unknown("the membership has no manifest".to_owned()))?;
        let statements = self.store.statements_held(id, session.lease.epoch);
        let verified = verify_origins(
            &origins,
            session.peer(),
            &manifest,
            &statements,
            &session.lease.channel_binding,
            ledger,
            now,
        )?;
        for left_out in &verified.unverified {
            tracing::warn!(
                event.name = "host.membership.import_origin_unverified",
                component = "host",
                origin = %uuid_text(left_out),
                resource = %ledger,
                "a required origin's manifest did not verify: it is not imported this pass"
            );
        }
        let checkpoint = &verified.checkpoint;
        let verified_at = self.time.now_secs();
        let mut state = importing
            .engine
            .import_state(ledger)
            .map_err(storage)?
            .unwrap_or(State {
                membership_id: *id,
                revision: checkpoint.revision,
                checkpoint: Vec::new(),
                verified_at,
                gaps: Vec::new(),
            });
        // Gaps are kept whatever the membership or the revision; the checkpoint is the new one.
        state.membership_id = *id;
        state.revision = checkpoint.revision;
        state.checkpoint = origins.checkpoint.clone();
        state.verified_at = verified_at;
        importing
            .engine
            .keep_import_state(ledger, &state)
            .map_err(storage)?;

        let mut budget = MAX_BATCHES_PER_PASS;
        let mut count = 0;
        let imported = async {
            for (origin, origin_manifest, pins) in &verified.origins {
                let from = ImportOrigin {
                    membership_id: origin.membership_id,
                    epoch: origin_manifest.epoch,
                    host_id: origin.host_id,
                    pins,
                };
                let Some(named) = checkpoint
                    .origins
                    .iter()
                    .find(|named| named.host_id == origin.host_id)
                else {
                    continue;
                };
                for run in &named.runs {
                    if state.gapped_from(&origin.host_id, &run.run).is_some() {
                        continue;
                    }
                    let held = importing
                        .engine
                        .held(ledger, &origin.host_id, &run.run)
                        .map_err(storage)?;
                    let mut next = held + 1;
                    if next < run.oldest_retained {
                        // The coordinator's retention passed what this Host holds.
                        self.gap(
                            &mut state,
                            origin.host_id,
                            run.run,
                            next,
                            Some(run.oldest_retained - 1),
                            RETENTION,
                            checkpoint.revision,
                        );
                        continue;
                    }
                    while next <= run.acked && budget > 0 {
                        budget -= 1;
                        let asked = self
                            .import_batch(
                                &mut session,
                                ledger,
                                &from,
                                run.run,
                                next,
                                importing.engine.as_ref(),
                            )
                            .await?;
                        match asked {
                            Step::Advanced(acked) if acked >= next => {
                                count += 1;
                                next = acked + 1;
                            }
                            Step::Advanced(_) => break,
                            Step::Gap(reason, at) => {
                                self.gap(
                                    &mut state,
                                    origin.host_id,
                                    run.run,
                                    at,
                                    None,
                                    reason,
                                    checkpoint.revision,
                                );
                                break;
                            }
                            Step::Stop => break,
                        }
                    }
                }
            }
            Ok::<(), MembershipError>(())
        }
        .await;
        // The gaps found are kept whatever ended the pass.
        importing
            .engine
            .keep_import_state(ledger, &state)
            .map_err(storage)?;
        imported.map(|()| count)
    }

    /// Asks for the batch covering `seq` and ingests it.
    async fn import_batch(
        &self,
        session: &mut MemberTask,
        ledger: &Resource,
        origin: &ImportOrigin<'_>,
        run: [u8; 16],
        seq: u64,
        engine: &dyn StreamImport,
    ) -> Result<Step, MembershipError> {
        let boot = self.identity.boot_id();
        let request = Request::Batch {
            host_id: origin.host_id,
            run,
            seq,
        };
        let body = match session
            .send(
                &request_id(
                    &boot,
                    &format!("{}-{}", hex(&origin.host_id), hex(&run)),
                    seq,
                ),
                request.encode()?,
            )
            .await
        {
            Ok(body) => body,
            Err(MembershipError::Remote { code, .. })
                if code == permguard_core::codes::stream::GONE =>
            {
                return Ok(Step::Gap(RETENTION, seq));
            }
            // Not held now, or not forwardable: asked again on a later pass.
            Err(MembershipError::Remote { code, reason }) => {
                tracing::info!(
                    event.name = "host.membership.import_deferred",
                    component = "host",
                    origin = %uuid_text(&origin.host_id),
                    resource = %ledger,
                    code = %code,
                    reason = %reason,
                    "the coordinator did not answer a batch: it is asked again on the next pass"
                );
                return Ok(Step::Stop);
            }
            Err(error) => return Err(error),
        };
        Ok(
            match engine
                .import(ledger, origin, &body)
                .map_err(MembershipError::Storage)?
            {
                Imported::Admitted { acked } | Imported::OutOfOrder { acked } => {
                    Step::Advanced(acked)
                }
                Imported::Gone { .. } => Step::Gap(RETENTION, seq),
                Imported::Fork { run: forked, at } => {
                    tracing::error!(
                        event.name = "host.membership.import_forked",
                        component = "host",
                        origin = %uuid_text(&origin.host_id),
                        resource = %ledger,
                        at_seq = at,
                        "an origin's batch differs from what this Host holds of it: its stream is closed here"
                    );
                    // A fork of another run closes this one where it was asked.
                    Step::Gap(FORK, if forked == run { at.max(1) } else { seq })
                }
                Imported::Unverifiable => {
                    tracing::error!(
                        event.name = "host.membership.import_unverifiable",
                        component = "host",
                        origin = %uuid_text(&origin.host_id),
                        resource = %ledger,
                        seq,
                        "an origin's batch does not verify under its pinned ring: nothing past it is imported"
                    );
                    Step::Gap(UNVERIFIABLE, seq)
                }
            },
        )
    }

    /// Keeps a gap of `origin`'s run `run` from `from`, once.
    #[allow(clippy::too_many_arguments)]
    fn gap(
        &self,
        state: &mut State,
        origin: [u8; 16],
        run: [u8; 16],
        from: u64,
        through: Option<u64>,
        reason: &str,
        revision: [u8; 32],
    ) {
        let kept = state.keep_gap(Gap {
            origin,
            run,
            from,
            through,
            reason: reason.to_owned(),
            detected_at: self.time.now_secs(),
            revision,
        });
        if kept {
            tracing::warn!(
                event.name = "host.membership.import_gap",
                component = "host",
                origin = %uuid_text(&origin),
                run = %hex(&run),
                from,
                reason,
                "a gap in the imported history: it stays until a snapshot or a change of the required origins"
            );
        }
    }
}

/// What one batch request came to.
enum Step {
    /// The run is held through this sequence.
    Advanced(u64),
    /// A gap opens at this sequence, for this reason.
    Gap(&'static str, u64),
    /// Nothing more of this run this pass.
    Stop,
}

#[cfg(test)]
mod tests;
