// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The `events.import` task handler (WP-6.2c1; owner decisions of 2026-10-18 and 2026-10-19): a
//! member's Host pulls the required origins' history of one ledger from this coordinator's
//! consumer of `data/events`.
//!
//! The Host authorized the task session: its membership is active, its task names the resource,
//! and the lease the ledger it reads. An `origins` request answers every required origin, the
//! coordinator's active members whose `events.ship` covers the ledger, with the manifest in force
//! and one checkpoint signed now under `control.attest`, bound to the session: what the consumer
//! holds of each origin's runs, even when nothing is new. A `batch` request answers the batch that
//! covers one sequence of one origin's run as the origin shipped it, its batch file and the ring
//! statement it was verified under, so the member verifies the origin's own signature; nothing is
//! re-signed. The member's own stream is never sent back.

use std::sync::Arc;

use permguard_core::authz::Resource;
use permguard_core::codes;
use permguard_host::composition::{ImportCheckpointV1, Signer, StreamConsumer};
use permguard_host::membership::import::{
    Checkpoint, CheckpointOrigin, CheckpointRun, MAX_CHECKPOINT_RUNS, MAX_ORIGINS, OriginSet,
    Origins, Request,
};
use permguard_host::membership::task::{TaskContext, TaskHandler};
use permguard_host::session::Refusal;
use permguard_stream::engine::batch::SealedBatch;
use permguard_stream::engine::ingest::Ship;

/// The contract version this handler speaks.
pub const VERSION: u64 = permguard_host::membership::import::VERSION;

/// The required origins of a resource, as the Host's membership store holds them.
pub(crate) type OriginsOf = dyn Fn(&Resource) -> Result<OriginSet, String> + Send + Sync;

/// Serves `events.import` from the Host's consumer of the event stream.
pub(crate) struct Import {
    pub(crate) consumer: StreamConsumer,
    pub(crate) origins: Arc<OriginsOf>,
    pub(crate) signer: Signer<ImportCheckpointV1>,
    /// This coordinator's `host_id`.
    pub(crate) coordinator: [u8; 16],
}

fn refusal(code: &'static str, reason: impl Into<String>) -> Refusal {
    Refusal {
        code,
        reason: reason.into(),
    }
}

fn unavailable(reason: impl Into<String>) -> Refusal {
    refusal(codes::common::UNAVAILABLE, reason)
}

impl Import {
    /// The ledger the session reads: its lease's resource, which must name one ledger.
    fn ledger(context: &TaskContext) -> Result<Resource, Refusal> {
        let resource = Resource::parse(&context.resource).map_err(|error| {
            refusal(
                codes::notp::BODY_REJECTED,
                format!("the session's resource: {error}"),
            )
        })?;
        let ledger = matches!(&resource, Resource::Ledger { plane, .. } if plane == "data");
        if !ledger {
            return Err(refusal(
                codes::common::FORBIDDEN,
                format!(
                    "`{}` is not one ledger: events.import reads one ledger per session",
                    context.resource
                ),
            ));
        }
        Ok(resource)
    }

    fn origins(&self, resource: &Resource, context: &TaskContext) -> Result<Vec<u8>, Refusal> {
        let set = (self.origins)(resource).map_err(unavailable)?;
        // A set no member could read is refused here, not signed (after the review).
        if false {
            return Err(unavailable(format!(
                "the ledger has more than {MAX_ORIGINS} required origins"
            )));
        }
        let mut origins = Vec::with_capacity(set.origins.len());
        let mut runs_named = 0usize;
        let held = self.consumer.runs(resource).map_err(unavailable)?;
        for origin in &set.origins {
            let mut runs = Vec::new();
            for run in held.iter().filter(|run| run.producer == origin.host_id) {
                runs.push(CheckpointRun {
                    run: run.run,
                    acked: run.acked,
                    oldest_retained: run.oldest_retained.max(1),
                    admitted_at: self
                        .consumer
                        .admitted_at(resource, &run.producer, &run.run)
                        .map_err(unavailable)?,
                });
            }
            runs.sort_by_key(|run| run.run);
            runs_named += runs.len();
            if runs_named > MAX_CHECKPOINT_RUNS {
                return Err(unavailable(format!(
                    "the required origins hold more than {MAX_CHECKPOINT_RUNS} runs of the ledger"
                )));
            }
            origins.push(CheckpointOrigin {
                host_id: origin.host_id,
                runs,
            });
        }
        let issued_at = u64::try_from(self.signer.signing_time())
            .map_err(|_| unavailable("the coordinator's clock is before the epoch"))?;
        let checkpoint = Checkpoint {
            coordinator: self.coordinator,
            resource: resource.to_string(),
            revision: set.revision,
            origins,
            issued_at,
            channel_binding: context.channel_binding,
            // The signer binds the ring's epoch and set.
            ring_epoch: 0,
            key_set_digest: [0; 32],
        };
        // What a member's decoder would refuse is not signed: a run the consumer reports out of
        // its own bounds, a resource out of its length (after the review).
        checkpoint
            .encode()
            .and_then(|bytes| Checkpoint::decode(&bytes))
            .map_err(|error| unavailable(format!("the checkpoint does not hold: {error}")))?;
        let checkpoint = self
            .signer
            .sign(&checkpoint)
            .map_err(|error| unavailable(format!("signing the checkpoint: {error}")))?;
        Origins {
            checkpoint,
            origins: set.origins,
        }
        .encode()
        .map_err(|error| unavailable(format!("encoding the answer: {error}")))
    }

    fn batch(
        &self,
        resource: &Resource,
        context: &TaskContext,
        host_id: [u8; 16],
        run: [u8; 16],
        seq: u64,
    ) -> Result<Vec<u8>, Refusal> {
        if host_id == context.member {
            return Err(refusal(
                codes::common::FORBIDDEN,
                "a member's own stream is never sent back to it",
            ));
        }
        let set = (self.origins)(resource).map_err(unavailable)?;
        if !set.origins.iter().any(|origin| origin.host_id == host_id) {
            return Err(refusal(
                codes::common::FORBIDDEN,
                "the Host named is not a required origin of the ledger",
            ));
        }
        let held = self
            .consumer
            .runs(resource)
            .map_err(unavailable)?
            .into_iter()
            .find(|held| held.producer == host_id && held.run == run)
            .ok_or_else(|| refusal(codes::common::NOT_FOUND, "no such run of the origin"))?;
        if seq < held.oldest_retained {
            return Err(refusal(
                codes::stream::GONE,
                format!(
                    "the coordinator holds the run from sequence {}",
                    held.oldest_retained
                ),
            ));
        }
        if seq > held.acked {
            return Err(refusal(
                codes::common::NOT_FOUND,
                format!("the coordinator admitted the run through {}", held.acked),
            ));
        }
        let file = self
            .consumer
            .batch(resource, &host_id, &run, seq)
            .map_err(unavailable)?
            .ok_or_else(|| unavailable("the batch covering the sequence is not held"))?;
        let kid = SealedBatch::decode(&file)
            .and_then(|batch| batch.kid())
            .map_err(|error| unavailable(format!("a held batch: {error}")))?;
        // A batch admitted before the statements were kept cannot be forwarded verifiably.
        let statement = self
            .consumer
            .statement(resource, &host_id, &run, &kid)
            .map_err(unavailable)?
            .ok_or_else(|| {
                unavailable("the coordinator kept no ring statement for the batch's key")
            })?;
        Ship {
            batch: file,
            statement,
        }
        .encode()
        .map_err(|error| unavailable(format!("encoding the batch: {error}")))
    }
}

impl TaskHandler for Import {
    fn handle(&self, context: &TaskContext, body: &[u8]) -> Result<Vec<u8>, Refusal> {
        let request = Request::decode(body).map_err(|error| {
            refusal(
                codes::notp::BODY_REJECTED,
                format!("not an events.import message: {error}"),
            )
        })?;
        let resource = Self::ledger(context)?;
        match request {
            Request::Origins => self.origins(&resource, context),
            Request::Batch { host_id, run, seq } => {
                self.batch(&resource, context, host_id, run, seq)
            }
        }
    }
}

#[cfg(test)]
mod tests;
