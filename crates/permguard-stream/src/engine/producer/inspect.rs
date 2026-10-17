// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! What a producer handle answers the Host API (WP-5.7a): its streams, runs, records, signers,
//! subscriptions and anchors, read from the streams it already holds, never one it would create.

use std::sync::Arc;

use permguard_host::api::streams::{
    AnchorView, Frontier, ProducerRun, RecordPage, ResourceState, RunAck, RunSigners, StreamView,
    SubscriptionView,
};

use super::super::anchor::{Anchor, anchor_in};
use super::super::reads::{Inspect, anchor_view, page_view, span_view};
use super::super::{RecordCodec, StreamError, hex};
use super::seal::spans_of;
use super::ship::{subscriptions_held, truncate_safe_of};
use super::{Physical, Producer, SubscriptionState};

/// One run as the journal holds it: `(run, fence, last_seq, ended)`.
type JournalRun = ([u8; 16], Option<[u8; 16]>, u64, bool);

impl<C: RecordCodec> Producer<C> {
    /// The stream of `resource` this producer holds, never one it would open anew: the open one,
    /// or the one whose directory exists; no other stream is opened (after the review).
    fn held(&self, resource: &str) -> Result<Option<Arc<Physical>>, StreamError> {
        let Ok(parsed) = permguard_core::authz::Resource::parse(resource) else {
            return Ok(None);
        };
        let Ok(key) = self.descriptor.key(&parsed, self.context.host_id) else {
            return Ok(None);
        };
        let mut streams = self
            .streams
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(open) = streams.get(&key.resource) {
            return Ok(Some(Arc::clone(open)));
        }
        let component = key.resource_component();
        if !self.context.dir.subdirs()?.contains(&component)
            || !self
                .context
                .dir
                .subdir(&component, false)?
                .subdirs()?
                .contains(&hex(&self.context.host_id))
        {
            return Ok(None);
        }
        let physical = Arc::new(Physical::open(
            &self.context,
            &self.descriptor,
            key.clone(),
        )?);
        streams.insert(key.resource, Arc::clone(&physical));
        Ok(Some(physical))
    }

    /// Each run `physical`'s journal holds, from STATE's base on, `(run, fence, last_seq,
    /// ended)`, read under one guard and writing nothing (after the review).
    fn journal_runs(physical: &Physical) -> Result<Vec<JournalRun>, StreamError> {
        let writer = physical.writer();
        let statement = |envelope: &[u8]| {
            super::super::run::RunStatement::decode(
                permguard_objects::cose::Sign1::decode(envelope)
                    .map_err(|error| StreamError::Invalid(error.to_string()))?
                    .payload_unverified(),
            )
        };
        let mut runs = Vec::new();
        if let Some(base) = writer.base() {
            let held = statement(&base.statement)?;
            runs.push((
                held.run_id,
                held.fence.map(|fence| fence.membership_id),
                base.last_seq,
                base.ended,
            ));
        }
        for frame in writer.journal.frames()? {
            match frame.kind {
                super::RUN_OPEN => {
                    let held = statement(&frame.payload)?;
                    runs.push((
                        held.run_id,
                        held.fence.map(|fence| fence.membership_id),
                        0,
                        false,
                    ));
                }
                super::RECORDS => {
                    let (first, group) = super::decode_group(&frame.payload)?;
                    if let Some(run) = runs.last_mut() {
                        run.2 = first + group.len() as u64 - 1;
                    }
                }
                super::TERMINAL => {
                    if let Some(run) = runs.last_mut() {
                        run.3 = true;
                    }
                }
                _ => {}
            }
        }
        Ok(runs)
    }

    /// The last sequence `run`'s batch files seal, read without creating their directory.
    fn sealed_of(physical: &Physical, run: &[u8; 16]) -> Result<u64, StreamError> {
        let writer = physical.writer();
        if !writer.dir.subdirs()?.iter().any(|name| name == "batches") {
            return Ok(0);
        }
        let batches = writer.dir.subdir("batches", false)?;
        let name = hex(run);
        if !batches.subdirs()?.contains(&name) {
            return Ok(0);
        }
        let dir = batches.subdir(&name, false)?;
        Ok(match super::seal::batches_of(&dir)?.last() {
            Some((_, last, _)) => *last,
            None => super::seal::pruned_of(&dir)?,
        })
    }

    /// The anchor of `run` in `physical`'s batches, when a prefix went.
    fn anchor_of(physical: &Physical, run: &[u8; 16]) -> Result<Option<Anchor>, StreamError> {
        let writer = physical.writer();
        if !writer.dir.subdirs()?.iter().any(|name| name == "batches") {
            return Ok(None);
        }
        let batches = writer.dir.subdir("batches", false)?;
        let name = hex(run);
        if !batches.subdirs()?.contains(&name) {
            return Ok(None);
        }
        anchor_in(&batches.subdir(&name, false)?)
    }

    /// The runs `physical`'s journal holds, in order.
    fn run_ids(physical: &Physical) -> Result<Vec<[u8; 16]>, StreamError> {
        Ok(Self::journal_runs(physical)?
            .into_iter()
            .map(|(run, ..)| run)
            .collect())
    }
}

impl<C: RecordCodec> Inspect for Producer<C> {
    fn role(&self) -> &'static str {
        "producer"
    }

    fn serves(&self, plane: &str, stream_type: &str) -> bool {
        self.descriptor.plane == plane && self.descriptor.stream_type == stream_type
    }

    fn view(&self) -> Result<StreamView, StreamError> {
        let mut resources = Vec::new();
        for physical in self.every()? {
            let writer = physical.writer();
            let state = match writer.state.as_ref() {
                Some(state) if state.forked_at_seq.is_some() => "forked",
                Some(state) if state.unshipped.is_some() => "behind",
                _ => "open",
            };
            resources.push(ResourceState {
                resource: physical.key.resource.clone(),
                state: state.to_owned(),
            });
        }
        Ok(StreamView {
            plane: self.descriptor.plane.clone(),
            stream_type: self.descriptor.stream_type.clone(),
            version: self.descriptor.version,
            role: "producer".to_owned(),
            retention: self.descriptor.retention.as_str().to_owned(),
            ring: self.descriptor.ring.to_owned(),
            task: self.descriptor.task.map(|task| task.as_str().to_owned()),
            resources,
        })
    }

    fn frontier(&self, resource: &str, into: &mut Frontier) -> Result<(), StreamError> {
        let Some(physical) = self.held(resource)? else {
            return Ok(());
        };
        // Read from the journal and the batch files alone: never through the sealer's survey,
        // which writes, and which refuses a forked stream (after the review).
        let subscriptions = subscriptions_held(&physical.writer().dir)?;
        for (run, fence, last_seq, ended) in Self::journal_runs(&physical)? {
            let low_watermark =
                Self::anchor_of(&physical, &run)?.map_or(1, |anchor| anchor.low_watermark);
            into.producer.push(ProducerRun {
                run: hex(&run),
                ended,
                last_seq,
                sealed: Self::sealed_of(&physical, &run)?,
                acknowledged: truncate_safe_of(&subscriptions, &run, fence),
                low_watermark,
            });
        }
        Ok(())
    }

    fn records(
        &self,
        resource: &str,
        run: Option<(&[u8; 16], &[u8; 16])>,
        from: u64,
        limit: usize,
    ) -> Result<Option<RecordPage>, StreamError> {
        if run.is_some() {
            return Ok(None);
        }
        let Some(physical) = self.held(resource)? else {
            return Ok(None);
        };
        let (current, last_seq) = {
            let writer = physical.writer();
            let Some(current) = writer.run.as_ref() else {
                return Ok(None);
            };
            (current.statement.run_id, current.last_seq)
        };
        let page = Self::page_of(&physical, from, limit)?;
        Ok(Some(page_view(
            "producer",
            &physical.key.producer_host_id,
            resource,
            &current,
            page,
            limit,
            last_seq,
            self.descriptor.record_domain,
        )?))
    }

    fn signers(&self, resource: &str) -> Result<Vec<RunSigners>, StreamError> {
        let Some(physical) = self.held(resource)? else {
            return Ok(Vec::new());
        };
        let spans = spans_of(&physical.writer().dir)?;
        Ok(spans
            .runs
            .iter()
            .map(|(run, spans)| RunSigners {
                role: "producer".to_owned(),
                producer: hex(&physical.key.producer_host_id),
                run: hex(run),
                spans: spans.iter().map(span_view).collect(),
            })
            .collect())
    }

    fn subscriptions(&self, resource: &str) -> Result<Vec<SubscriptionView>, StreamError> {
        let Some(physical) = self.held(resource)? else {
            return Ok(Vec::new());
        };
        let subscriptions = subscriptions_held(&physical.writer().dir)?;
        Ok(subscriptions
            .into_iter()
            .map(|subscription| {
                let (state, reason) = match &subscription.state {
                    SubscriptionState::Active => ("active", None),
                    SubscriptionState::Paused { .. } => ("paused", None),
                    SubscriptionState::Stopped { reason } => ("stopped", Some(reason.clone())),
                };
                SubscriptionView {
                    membership: permguard_host::identity::record::uuid_text(
                        &subscription.membership_id,
                    ),
                    task: subscription.task_id.clone(),
                    required: subscription.required,
                    state: state.to_owned(),
                    reason,
                    acked: subscription
                        .runs
                        .iter()
                        .map(|(run, acked)| RunAck {
                            run: hex(run),
                            acked: *acked,
                        })
                        .collect(),
                }
            })
            .collect())
    }

    fn anchors(&self, resource: &str) -> Result<Vec<AnchorView>, StreamError> {
        let Some(physical) = self.held(resource)? else {
            return Ok(Vec::new());
        };
        let mut anchors = Vec::new();
        for run in Self::run_ids(&physical)? {
            if let Some(anchor) = Self::anchor_of(&physical, &run)? {
                anchors.push(anchor_view(
                    "producer",
                    &physical.key.producer_host_id,
                    &anchor,
                )?);
            }
        }
        Ok(anchors)
    }
}
