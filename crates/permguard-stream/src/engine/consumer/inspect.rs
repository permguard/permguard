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

/// The batch files in `dir`, `(first, last, name)` by first sequence.
fn batch_files(dir: &permguard_host::storage::Dir) -> Result<Vec<(u64, u64, String)>, StreamError> {
    let mut found: Vec<(u64, u64, String)> = dir
        .names()?
        .into_iter()
        .filter_map(|name| {
            let (first, last) = name.strip_suffix(".jws")?.split_once('-')?;
            Some((first.parse().ok()?, last.parse().ok()?, name))
        })
        .collect();
    found.sort();
    Ok(found)
}

fn wrap(error: StreamError) -> String {
    error.to_string()
}

impl<C: RecordCodec> permguard_host::composition::StreamConsumerReads for Consumer<C> {
    fn runs(
        &self,
        resource: &Resource,
    ) -> Result<Vec<permguard_host::composition::ConsumedRun>, String> {
        let mut found = Vec::new();
        for (key, run) in self.runs_of(resource).map_err(wrap)? {
            let Some(dir) = self.run_dir(&key, &run).map_err(wrap)? else {
                continue;
            };
            let state = permguard_host::storage::write::read_view(
                &dir,
                super::STATE,
                permguard_host::storage::format::VIEW,
            )
            .map_err(|error| error.to_string())?
            .map(|bytes| super::ConsumerState::decode(&bytes))
            .transpose()
            .map_err(wrap)?;
            found.push((
                hex(&key.producer_host_id),
                state.and_then(|state| state.opened).unwrap_or_default(),
                hex(&run),
                permguard_host::composition::ConsumedRun {
                    producer: key.producer_host_id,
                    run,
                    acked: state.map_or(0, |state| state.acked),
                    oldest_retained: state.map_or(1, |state| state.oldest_retained),
                },
            ));
        }
        // By producer, then the order the consumer first admitted the runs, kept in each STATE;
        // the run id breaks a tie (owner decision of 2026-10-18, after the review).
        found.sort_by(|left, right| (&left.0, left.1, &left.2).cmp(&(&right.0, right.1, &right.2)));
        Ok(found.into_iter().map(|(.., run)| run).collect())
    }

    fn locate(&self, producer: &[u8; 16], run: &[u8; 16]) -> Result<Option<Resource>, String> {
        let Some((key, _)) = self
            .runs()
            .map_err(wrap)?
            .into_iter()
            .find(|(key, held)| key.producer_host_id == *producer && held == run)
        else {
            return Ok(None);
        };
        Resource::parse(&key.resource)
            .map(Some)
            .map_err(|error| error.to_string())
    }

    fn records(
        &self,
        resource: &Resource,
        producer: &[u8; 16],
        run: &[u8; 16],
        from: u64,
        limit: usize,
    ) -> Result<permguard_host::composition::ConsumedPage, String> {
        let page = self
            .read_raw(resource, *producer, *run, from, limit)
            .map_err(wrap)?;
        Ok(permguard_host::composition::ConsumedPage {
            records: page.records,
            low_watermark: page.gap.map(|gap| gap.low_watermark),
        })
    }

    fn batch(
        &self,
        resource: &Resource,
        producer: &[u8; 16],
        run: &[u8; 16],
        seq: u64,
    ) -> Result<Option<Vec<u8>>, String> {
        let key = self.descriptor.key(resource, *producer).map_err(wrap)?;
        let Some(dir) = self.run_dir(&key, run).map_err(wrap)? else {
            return Ok(None);
        };
        let Some(batches) = super::child(&dir, super::BATCHES, false).map_err(wrap)? else {
            return Ok(None);
        };
        let Some((_, _, name)) = batch_files(&batches)
            .map_err(wrap)?
            .into_iter()
            .find(|(first, last, _)| (*first..=*last).contains(&seq))
        else {
            return Ok(None);
        };
        batches.read(&name).map_err(|error| error.to_string())
    }

    fn statement(
        &self,
        resource: &Resource,
        producer: &[u8; 16],
        run: &[u8; 16],
        kid: &str,
    ) -> Result<Option<Vec<u8>>, String> {
        let key = self.descriptor.key(resource, *producer).map_err(wrap)?;
        let Some(dir) = self.run_dir(&key, run).map_err(wrap)? else {
            return Ok(None);
        };
        let Some(statements) = super::child(&dir, super::STATEMENTS, false).map_err(wrap)? else {
            return Ok(None);
        };
        // Of the statements naming the key, the latest epoch's: the set the run moved on to.
        let mut found: Option<(u64, Vec<u8>)> = None;
        for name in statements.names().map_err(|error| error.to_string())? {
            // A statement a crash left half-published is no statement (after the review).
            if name.starts_with(permguard_host::storage::dir::TEMP_PREFIX) {
                continue;
            }
            let Some(bytes) = statements.read(&name).map_err(|error| error.to_string())? else {
                continue;
            };
            let statement = permguard_host::membership::record::RingStatement::decode(&bytes)
                .map_err(|error| format!("a kept ring statement: {error}"))?;
            let names_key = statement.keys.iter().any(|text| {
                serde_json::from_str::<permguard_core::keys::Jwk>(text)
                    .is_ok_and(|jwk| jwk.kid == kid)
            });
            if names_key
                && found
                    .as_ref()
                    .is_none_or(|(epoch, _)| statement.epoch > *epoch)
            {
                found = Some((statement.epoch, bytes));
            }
        }
        Ok(found.map(|(_, bytes)| bytes))
    }

    fn resources(&self) -> Result<Vec<Resource>, String> {
        let mut found: Vec<Resource> = Vec::new();
        for (key, _) in self.runs().map_err(wrap)? {
            let resource = Resource::parse(&key.resource).map_err(|error| error.to_string())?;
            if !found.contains(&resource) {
                found.push(resource);
            }
        }
        Ok(found)
    }

    fn import_state(
        &self,
        resource: &Resource,
    ) -> Result<Option<permguard_host::membership::import::State>, String> {
        permguard_host::composition::StreamImport::import_state(self, resource)
    }

    fn retain_above(
        &self,
        floor: std::sync::Arc<dyn permguard_host::composition::StreamFloor>,
    ) -> Result<(), String> {
        *self
            .floor
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(std::sync::Arc::new(
            super::super::retention::PlaneFloor(floor),
        ));
        self.plane_floor
            .store(true, std::sync::atomic::Ordering::SeqCst);
        Ok(())
    }

    fn admitted_at(
        &self,
        resource: &Resource,
        producer: &[u8; 16],
        run: &[u8; 16],
    ) -> Result<Option<u64>, String> {
        let key = self.descriptor.key(resource, *producer).map_err(wrap)?;
        Ok(self
            .with_held(&key, *run, false, |held| {
                Ok(held.admitted.last().map(|(_, at)| *at))
            })
            .map_err(wrap)?
            .flatten())
    }

    fn signers(
        &self,
        resource: &Resource,
    ) -> Result<Vec<permguard_host::composition::ConsumedSigners>, String> {
        let acked: Vec<([u8; 16], [u8; 16], u64)> =
            permguard_host::composition::StreamConsumerReads::runs(self, resource)?
                .into_iter()
                .map(|run| (run.producer, run.run, run.acked))
                .collect();
        let mut found = Vec::new();
        for (key, run) in self.runs_of(resource).map_err(wrap)? {
            let Some(dir) = self.run_dir(&key, &run).map_err(wrap)? else {
                continue;
            };
            let spans = match permguard_host::storage::write::read_view(
                &dir,
                super::SIGNERS,
                permguard_host::storage::format::VIEW,
            )
            .map_err(|error| error.to_string())?
            {
                Some(bytes) => super::super::producer::Spans::decode(&bytes).map_err(wrap)?,
                None => super::super::producer::Spans::default(),
            };
            let held = spans
                .runs
                .into_iter()
                .find(|(held, _)| *held == run)
                .map(|(_, spans)| spans)
                .unwrap_or_default();
            found.push(permguard_host::composition::ConsumedSigners {
                producer: key.producer_host_id,
                run,
                acked: acked
                    .iter()
                    .find(|(producer, held, _)| *producer == key.producer_host_id && *held == run)
                    .map_or(0, |(.., acked)| *acked),
                spans: held
                    .into_iter()
                    .map(|span| (span.from_seq, span.kid, span.jwk))
                    .collect(),
            });
        }
        Ok(found)
    }
}
