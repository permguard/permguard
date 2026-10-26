// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The drain receipt a Host issues for itself (TD-2).
//!
//! What a recovery drain prints once every stream it produces is acknowledged by every required
//! subscription through its last sequence: the signed receipt (`operations::drain`) and the Host's
//! verification bundle, for the drain controller to check against the identity pin the coordinator
//! holds. A run still behind, or holding records no required subscription acknowledges, is refused
//! here, so a receipt is never issued while the volume holds the only copy of a record.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use serde::{Deserialize, Serialize};

use super::HostApi;
use super::keys::KeyBundleQuery;
use crate::keys::ring::HOST_OPERATIONS;
use crate::operations::drain::{DrainReceipt, DrainedStream, sign};

/// The receipt and the bundle that verifies it, as a recovery drain prints them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DrainReceiptExport {
    /// The COSE_Sign1 `permguard.drain.receipt.v1`, base64url.
    pub receipt: String,
    /// The Host's verification bundle, in the shape `host keys bundle export` writes.
    pub bundle: BundleExport,
}

/// A whole verification bundle: its signed manifest and every item, base64url.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BundleExport {
    pub resource: String,
    pub manifest: String,
    pub bundle_digest: String,
    pub items: Vec<String>,
}

impl HostApi {
    /// Issues the drain receipt of this process's volume, timed by the Host's clock guard (WP-2.12):
    /// every run of every stream this Host produces and ships, each acknowledged through its last
    /// sequence by its required subscriptions, or a refusal.
    pub fn drain_receipt(&self) -> Result<DrainReceiptExport, String> {
        self.drain_receipt_at(self.time.now_secs())
    }

    /// [`HostApi::drain_receipt`] at `drained_at`, seconds since the Unix epoch.
    pub(crate) fn drain_receipt_at(&self, drained_at: u64) -> Result<DrainReceiptExport, String> {
        let (volume_id, generation) = self
            .volume
            .ok_or("no claimed volume is named to this facade: a receipt names the volume")?;
        let identity = self
            .keys
            .identity()
            .ok_or("no Host identity is open on this process")?;
        let ring = self.keys.ring(HOST_OPERATIONS).ok_or_else(|| {
            format!(
                "a drain receipt is signed under `{HOST_OPERATIONS}`, which this Host does not hold"
            )
        })?;
        let streams = match self.streams.as_deref() {
            None => Vec::new(),
            Some(reads) => drained_streams(reads)?,
        };
        let receipt = DrainReceipt {
            host_id: identity.host_id(),
            volume_id,
            generation,
            drained_at,
            streams,
        };
        let envelope = sign(ring, &receipt)?;
        Ok(DrainReceiptExport {
            receipt: B64.encode(envelope),
            bundle: self.whole_bundle()?,
        })
    }

    /// The Host's whole verification bundle, every page of one frontier.
    fn whole_bundle(&self) -> Result<BundleExport, String> {
        let resource = permguard_core::authz::Resource::host();
        let query = |frontier: Option<String>, cursor: Option<String>| KeyBundleQuery {
            resource: "host".to_owned(),
            frontier,
            cursor,
            limit: None,
        };
        let first = self
            .key_bundle_page(&query(None, None), &resource)
            .map_err(|refusal| format!("the verification bundle: {refusal:?}"))?;
        let mut items = first.items.clone();
        let mut cursor = first.next_cursor.clone();
        while let Some(next) = cursor {
            let page = self
                .key_bundle_page(&query(Some(first.manifest.clone()), Some(next)), &resource)
                .map_err(|refusal| format!("the verification bundle: {refusal:?}"))?;
            items.extend(page.items);
            cursor = page.next_cursor;
        }
        Ok(BundleExport {
            resource: first.resource,
            manifest: first.manifest,
            bundle_digest: first.bundle_digest,
            items,
        })
    }
}

/// Every producer run that holds records, of every stream this Host produces, each acknowledged
/// through its last sequence by its required subscriptions.
///
/// Fail-closed (TD-2, decided under the owner's delegation): a run holding records that no
/// required subscription acknowledges — a stream no task ships, a run recorded before any
/// membership fenced one, a subscription not required — refuses the receipt, because the volume
/// would be its only copy. Only a run without records, or one whose prefix is gone, owes nothing.
fn drained_streams(reads: &dyn super::streams::StreamReads) -> Result<Vec<DrainedStream>, String> {
    let mut drained = Vec::new();
    for view in reads.list()? {
        if view.role != "producer" {
            continue;
        }
        for state in &view.resources {
            let frontier = reads
                .frontier(&view.plane, &view.stream_type, &state.resource)?
                .ok_or_else(|| {
                    format!(
                        "the stream {}/{} serves no frontier for {}",
                        view.plane, view.stream_type, state.resource
                    )
                })?;
            for run in frontier.producer {
                let holds_records = run.last_seq > 0 && run.last_seq >= run.low_watermark;
                if !holds_records {
                    continue;
                }
                let acknowledged = match run.acknowledged {
                    Some(acknowledged) if acknowledged >= run.last_seq => acknowledged,
                    Some(acknowledged) => {
                        return Err(format!(
                            "the stream {}/{} of {} (run {}) is acknowledged through {} of {}: \
                             the drain did not complete, and no receipt is issued",
                            view.plane,
                            view.stream_type,
                            state.resource,
                            run.run,
                            acknowledged,
                            run.last_seq
                        ));
                    }
                    None => {
                        return Err(format!(
                            "the stream {}/{} of {} (run {}) holds records through {} that no \
                             required subscription acknowledges: the volume is their only copy, \
                             and no receipt is issued",
                            view.plane, view.stream_type, state.resource, run.run, run.last_seq
                        ));
                    }
                };
                drained.push(DrainedStream {
                    plane: view.plane.clone(),
                    stream_type: view.stream_type.clone(),
                    resource: state.resource.clone(),
                    run: run.run,
                    last_seq: run.last_seq,
                    acknowledged,
                });
            }
        }
    }
    Ok(drained)
}

#[cfg(test)]
mod tests;
