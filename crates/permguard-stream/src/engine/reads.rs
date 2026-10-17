// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The Host API's stream reads over the engine (WP-5.7a): every producer and consumer handle the
//! server serves, answering the Host's [`StreamReads`] by plane and type. A read never creates a
//! stream, a directory or a run it does not find.

use std::sync::Arc;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use permguard_host::api::streams::{
    AnchorView, Frontier, GapEntry, RecordPage, RecordView, RunSigners, SpanView, StreamReads,
    StreamView, SubscriptionView,
};

use super::anchor::{Anchor, Page};
use super::{StreamError, hex};

/// What one producer or consumer handle answers of its streams.
pub trait Inspect: Send + Sync {
    /// `producer` or `consumer`.
    fn role(&self) -> &'static str;
    /// Whether the handle's descriptor is `plane/stream_type`.
    fn serves(&self, plane: &str, stream_type: &str) -> bool;
    fn view(&self) -> Result<StreamView, StreamError>;
    fn frontier(&self, resource: &str, into: &mut Frontier) -> Result<(), StreamError>;
    /// The page of the producer's current run (`run` `None`) or of the consumer run named;
    /// `None` when this handle does not hold it.
    fn records(
        &self,
        resource: &str,
        run: Option<(&[u8; 16], &[u8; 16])>,
        from: u64,
        limit: usize,
    ) -> Result<Option<RecordPage>, StreamError>;
    fn signers(&self, resource: &str) -> Result<Vec<RunSigners>, StreamError>;
    fn subscriptions(&self, resource: &str) -> Result<Vec<SubscriptionView>, StreamError>;
    fn anchors(&self, resource: &str) -> Result<Vec<AnchorView>, StreamError>;
}

/// The view of a run's anchor.
pub(crate) fn anchor_view(
    role: &str,
    producer: &[u8; 16],
    anchor: &Anchor,
) -> Result<AnchorView, StreamError> {
    Ok(AnchorView {
        role: role.to_owned(),
        producer: hex(producer),
        run: hex(&anchor.run),
        through: anchor.through,
        low_watermark: anchor.low_watermark,
        terminal_head: anchor.terminal_head.clone(),
        covering: anchor.covering.len() as u64,
        anchor: URL_SAFE_NO_PAD.encode(anchor.encode()?),
    })
}

/// The page view of `page` of `run`, its records digested under `domain`.
#[allow(clippy::too_many_arguments)]
pub(crate) fn page_view(
    role: &str,
    producer: &[u8; 16],
    resource: &str,
    run: &[u8; 16],
    page: Page<Vec<u8>>,
    limit: usize,
    held_through: u64,
    domain: &str,
) -> Result<RecordPage, StreamError> {
    let next = page
        .records
        .last()
        .map(|(seq, _)| seq + 1)
        .filter(|next| page.records.len() == limit && *next <= held_through);
    Ok(RecordPage {
        resource: resource.to_owned(),
        run: hex(run),
        records: page
            .records
            .iter()
            .map(|(seq, bytes)| RecordView {
                seq: *seq,
                record: URL_SAFE_NO_PAD.encode(bytes),
                digest: super::batch::digest_string(domain, bytes),
            })
            .collect(),
        next,
        gap: page
            .gap
            .map(|gap| {
                Ok::<_, StreamError>(permguard_host::api::streams::GapView {
                    low_watermark: gap.low_watermark,
                    anchor: anchor_view(role, producer, &gap.anchor)?,
                })
            })
            .transpose()?,
    })
}

/// Every handle the server serves, answering the Host API.
#[derive(Default)]
pub struct Reads {
    handles: Vec<Arc<dyn Inspect>>,
}

impl Reads {
    /// These and `handle`.
    pub fn with(mut self, handle: Arc<dyn Inspect>) -> Self {
        self.handles.push(handle);
        self
    }

    fn serving(&self, plane: &str, stream_type: &str) -> Vec<&Arc<dyn Inspect>> {
        self.handles
            .iter()
            .filter(|handle| handle.serves(plane, stream_type))
            .collect()
    }
}

fn text(error: StreamError) -> String {
    error.to_string()
}

impl StreamReads for Reads {
    fn list(&self) -> Result<Vec<StreamView>, String> {
        self.handles
            .iter()
            .map(|handle| handle.view().map_err(text))
            .collect()
    }

    fn frontier(
        &self,
        plane: &str,
        stream_type: &str,
        resource: &str,
    ) -> Result<Option<Frontier>, String> {
        let handles = self.serving(plane, stream_type);
        if handles.is_empty() {
            return Ok(None);
        }
        let mut frontier = Frontier {
            resource: resource.to_owned(),
            ..Frontier::default()
        };
        for handle in handles {
            handle.frontier(resource, &mut frontier).map_err(text)?;
        }
        Ok(Some(frontier))
    }

    fn records(
        &self,
        plane: &str,
        stream_type: &str,
        resource: &str,
        run: Option<(&[u8; 16], &[u8; 16])>,
        from: u64,
        limit: usize,
    ) -> Result<Option<RecordPage>, String> {
        let handles = self.serving(plane, stream_type);
        if handles.is_empty() {
            return Ok(None);
        }
        for handle in handles {
            if let Some(page) = handle.records(resource, run, from, limit).map_err(text)? {
                return Ok(Some(page));
            }
        }
        // A stream served, a run it does not hold: an empty page, never an error that says
        // more than the caller asked.
        Ok(Some(RecordPage {
            resource: resource.to_owned(),
            run: run.map(|(_, run)| hex(run)).unwrap_or_default(),
            records: Vec::new(),
            next: None,
            gap: None,
        }))
    }

    fn signers(
        &self,
        plane: &str,
        stream_type: &str,
        resource: &str,
    ) -> Result<Option<Vec<RunSigners>>, String> {
        self.collect(plane, stream_type, |handle| handle.signers(resource))
    }

    fn subscriptions(
        &self,
        plane: &str,
        stream_type: &str,
        resource: &str,
    ) -> Result<Option<Vec<SubscriptionView>>, String> {
        self.collect(plane, stream_type, |handle| handle.subscriptions(resource))
    }

    fn gaps(
        &self,
        plane: &str,
        stream_type: &str,
        resource: &str,
    ) -> Result<Option<Vec<GapEntry>>, String> {
        Ok(self.anchors(plane, stream_type, resource)?.map(|anchors| {
            anchors
                .into_iter()
                .map(|anchor| GapEntry {
                    role: anchor.role,
                    producer: anchor.producer,
                    run: anchor.run,
                    low_watermark: anchor.low_watermark,
                })
                .collect()
        }))
    }

    fn anchors(
        &self,
        plane: &str,
        stream_type: &str,
        resource: &str,
    ) -> Result<Option<Vec<AnchorView>>, String> {
        self.collect(plane, stream_type, |handle| handle.anchors(resource))
    }
}

impl Reads {
    fn collect<T>(
        &self,
        plane: &str,
        stream_type: &str,
        read: impl Fn(&Arc<dyn Inspect>) -> Result<Vec<T>, StreamError>,
    ) -> Result<Option<Vec<T>>, String> {
        let handles = self.serving(plane, stream_type);
        if handles.is_empty() {
            return Ok(None);
        }
        let mut all = Vec::new();
        for handle in handles {
            all.extend(read(handle).map_err(text)?);
        }
        Ok(Some(all))
    }
}

/// `span` as the Host API shows it.
pub(crate) fn span_view(span: &super::producer::Span) -> SpanView {
    SpanView {
        from_seq: span.from_seq,
        kid: span.kid.clone(),
        jwk: span.jwk.clone(),
    }
}
