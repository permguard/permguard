// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! What a consumer handle answers the Host API (WP-5.7a): the runs it holds of each producer,
//! their records, signers and anchors, read without creating anything.

use permguard_core::authz::Resource;
use permguard_host::api::streams::{
    AnchorView, ConsumerRun, Frontier, RecordPage, ResourceState, RunSigners, StreamView,
    SubscriptionView,
};

use super::super::anchor::anchor_in;
use super::super::reads::{Inspect, anchor_view, page_view, span_view};
use super::super::{RecordCodec, StreamError, StreamKey, hex};
use super::{Consumer, FORKED};

impl<C: RecordCodec> Consumer<C> {
    /// The runs held of `resource`, `(key, run)`.
    fn held_runs(&self, resource: &str) -> Result<Vec<(StreamKey, [u8; 16])>, StreamError> {
        Ok(self
            .runs()?
            .into_iter()
            .filter(|(key, _)| key.resource == resource)
            .collect())
    }

    /// The directory of `key`'s run `run`, when it exists: read without opening its journal.
    fn run_dir(
        &self,
        key: &StreamKey,
        run: &[u8; 16],
    ) -> Result<Option<permguard_host::storage::Dir>, StreamError> {
        let Some(producer) = self.producer_dir(key, false)? else {
            return Ok(None);
        };
        super::child(&producer, &hex(run), false)
    }
}

impl<C: RecordCodec> Inspect for Consumer<C> {
    fn role(&self) -> &'static str {
        "consumer"
    }

    fn serves(&self, plane: &str, stream_type: &str) -> bool {
        self.descriptor.plane == plane && self.descriptor.stream_type == stream_type
    }

    fn view(&self) -> Result<StreamView, StreamError> {
        let mut resources: Vec<ResourceState> = Vec::new();
        for (key, _) in self.runs()? {
            if resources.iter().any(|held| held.resource == key.resource) {
                continue;
            }
            let forked = self
                .producer_dir(&key, false)?
                .is_some_and(|dir| dir.exists(FORKED).unwrap_or(false));
            resources.push(ResourceState {
                resource: key.resource.clone(),
                state: if forked { "forked" } else { "held" }.to_owned(),
            });
        }
        Ok(StreamView {
            plane: self.descriptor.plane.clone(),
            stream_type: self.descriptor.stream_type.clone(),
            version: self.descriptor.version,
            role: "consumer".to_owned(),
            retention: self.descriptor.retention.as_str().to_owned(),
            ring: self.descriptor.ring.to_owned(),
            task: self.descriptor.task.map(|task| task.as_str().to_owned()),
            resources,
        })
    }

    fn frontier(&self, resource: &str, into: &mut Frontier) -> Result<(), StreamError> {
        // From each run's STATE, written after its records: no journal is opened (after the
        // review).
        for (key, run) in self.held_runs(resource)? {
            let Some(dir) = self.run_dir(&key, &run)? else {
                continue;
            };
            let state = permguard_host::storage::write::read_view(
                &dir,
                super::STATE,
                permguard_host::storage::format::VIEW,
            )?
            .map(|bytes| super::ConsumerState::decode(&bytes))
            .transpose()?;
            into.consumer.push(ConsumerRun {
                producer: hex(&key.producer_host_id),
                run: hex(&run),
                acked: state.map_or(0, |state| state.acked),
                oldest_retained: state.map_or(1, |state| state.oldest_retained),
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
        let Some((producer, run)) = run else {
            return Ok(None);
        };
        let Some((key, _)) = self
            .held_runs(resource)?
            .into_iter()
            .find(|(key, held)| key.producer_host_id == *producer && held == run)
        else {
            return Ok(None);
        };
        let parsed =
            Resource::parse(resource).map_err(|error| StreamError::Invalid(error.to_string()))?;
        let acked = self
            .with_held(&key, *run, false, |held| Ok(held.acked))?
            .unwrap_or(0);
        let page = self.read_raw(&parsed, *producer, *run, from, limit)?;
        Ok(Some(page_view(
            "consumer",
            producer,
            resource,
            run,
            page,
            limit,
            acked,
            self.descriptor.record_domain,
        )?))
    }

    fn signers(&self, resource: &str) -> Result<Vec<RunSigners>, StreamError> {
        let mut found = Vec::new();
        for (key, run) in self.held_runs(resource)? {
            let Some(dir) = self.run_dir(&key, &run)? else {
                continue;
            };
            let spans = match permguard_host::storage::write::read_view(
                &dir,
                super::SIGNERS,
                permguard_host::storage::format::VIEW,
            )? {
                Some(bytes) => super::super::producer::Spans::decode(&bytes)?,
                None => super::super::producer::Spans::default(),
            };
            for (held, spans) in &spans.runs {
                if *held == run {
                    found.push(RunSigners {
                        role: "consumer".to_owned(),
                        producer: hex(&key.producer_host_id),
                        run: hex(&run),
                        spans: spans.iter().map(span_view).collect(),
                    });
                }
            }
        }
        Ok(found)
    }

    fn subscriptions(&self, _resource: &str) -> Result<Vec<SubscriptionView>, StreamError> {
        // A consumer is subscribed to, it keeps no subscription of its own.
        Ok(Vec::new())
    }

    fn anchors(&self, resource: &str) -> Result<Vec<AnchorView>, StreamError> {
        let mut found = Vec::new();
        for (key, run) in self.held_runs(resource)? {
            let Some(dir) = self.run_dir(&key, &run)? else {
                continue;
            };
            if let Some(anchor) = anchor_in(&dir)? {
                found.push(anchor_view("consumer", &key.producer_host_id, &anchor)?);
            }
        }
        Ok(found)
    }
}
