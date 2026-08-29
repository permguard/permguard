// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! Importing history other planes recorded.
//!
//! # Why this exists, and why it is off by default
//!
//! Several data planes may contribute events to one ledger, and a policy that asks "has this user
//! logged in within the hour" wants the answer across all of them. Pull is how a plane sees the
//! others' events.
//!
//! It is opt-in per plane and per ledger because turning it on **changes what the policies mean**.
//! A plane that silently began deciding against another plane's history would answer the same
//! request differently, with nothing in the request or the ledger to explain why. So the default is
//! `local`, and the mode a decision ran under travels in the response and in the decision log.
//!
//! # What is verified before anything is imported
//!
//! The origin signature, the record digests, the Merkle inclusion, and the tenant binding — in that
//! order, and all of it before a record is written. An imported record is evidence somebody else
//! produced: this plane can vouch that it arrived unaltered from a producer it trusts, and it can
//! vouch for nothing else.
//!
//! # What an imported record is never allowed to become
//!
//! Its own. Imported records keep their origin `(producer_class, producer_id, instance, sequence)`,
//! are never signed by this plane, and are never shipped back. A plane that re-signed what it
//! imported would be attesting that it recorded something it did not, and two planes importing from
//! each other would multiply one occurrence for ever.

use std::collections::BTreeSet;
use std::sync::Arc;

use permguard_control_client::events::{
    EventReader, ReadError, ReadFilters, ReadScope, ReadWindow,
};
use permguard_core::{Jwk, Metrics};
use permguard_events::envelope::Signed;
use permguard_events::record;
use serde_json::Value;
use tracing::{info, warn};

use super::imports::Imports;
use super::measure;

const COMPONENT: &str = "temporal";

/// How many records one round imports at most.
///
/// Bounded so a plane that has been offline for a day catches up over several rounds rather than
/// in one that holds a day of history in memory.
pub const MAX_PER_ROUND: usize = 1_000;

/// What one round concluded, for one subscription.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Round {
    /// Nothing new.
    Idle,
    /// Records were verified and imported.
    Imported {
        /// How many were new here.
        records: usize,
        /// How many were already held, by origin position or by logical occurrence.
        duplicates: usize,
    },
    /// The control plane could not answer. Nothing was imported, and nothing is lost.
    Deferred(String),
    /// Records arrived that this plane will not import, and they are quarantined.
    ///
    /// Not a retry: a record that fails verification will fail it again, and one whose type this
    /// plane cannot validate will not become valid by asking twice.
    Quarantined {
        /// How many, and why the first of them was refused.
        records: usize,
        reason: String,
    },
}

/// One subscription: a ledger, and the registered types this plane will import from it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Subscription {
    pub zone: String,
    pub ledger: String,
    /// The registered event types. Part of the canonical filter set the cursor is bound to.
    pub event_types: Vec<String>,
}

/// Reads verified history from the control plane into this plane's import store.
pub struct Puller {
    reader: Box<dyn EventReader + Send + Sync>,
    imports: Arc<Imports>,
    subscriptions: Vec<Subscription>,
    /// The producers whose signatures this plane accepts.
    keys: Vec<Jwk>,
    /// The event types this build can validate, and therefore import.
    accepted_types: Vec<String>,
    /// The consistency this plane decides under, recorded on any hole this loop discovers.
    ///
    /// A gap means different things under different modes — `shared-bounded` stops deciding,
    /// `shared-eventual` decides and says it is degraded — so the mode in force when the hole
    /// appeared is part of the record rather than something read back later from a configuration
    /// that may since have changed.
    consistency: permguard_core::config::Consistency,
    metrics: Metrics,
}

impl Puller {
    /// Builds a puller for these subscriptions.
    pub fn new(
        reader: Box<dyn EventReader + Send + Sync>,
        imports: Arc<Imports>,
        subscriptions: Vec<Subscription>,
        keys: Vec<Jwk>,
        consistency: permguard_core::config::Consistency,
        metrics: Metrics,
    ) -> Self {
        Self {
            reader,
            imports,
            subscriptions,
            keys,
            consistency,
            // One entry: the only registered consumer and validator this build carries. A
            // subscription naming anything else is refused rather than imported unvalidated.
            accepted_types: vec![permguard_languages::event::EVENT_TYPE.to_owned()],
            metrics,
        }
    }

    /// Runs one round over every subscription.
    pub fn round(&self) -> Vec<(Subscription, Round)> {
        self.subscriptions
            .iter()
            .map(|subscription| (subscription.clone(), self.pull(subscription)))
            .collect()
    }

    /// One subscription's round.
    pub fn pull(&self, subscription: &Subscription) -> Round {
        let labels = [
            ("zone", subscription.zone.as_str()),
            ("ledger", subscription.ledger.as_str()),
        ];
        // A type this build cannot validate is refused here rather than imported and discovered at
        // evaluation: the cursor must not advance over records nothing checked.
        if let Some(unknown) = subscription
            .event_types
            .iter()
            .find(|held| !self.accepted_types.contains(held))
        {
            return Round::Quarantined {
                records: 0,
                reason: format!(
                    "this subscription names `{unknown}`, and this build registers no validator \
                     for it: importing it would put records in the history that nothing checked"
                ),
            };
        }

        let cursor = match self
            .imports
            .cursor(&subscription.zone, &subscription.ledger)
        {
            Ok(cursor) => cursor,
            Err(error) => return Round::Deferred(error.to_string()),
        };
        let window = ReadWindow {
            from: cursor,
            until: None,
            limit_records: MAX_PER_ROUND,
            limit_bytes: 0,
            // The envelopes and paths are the point: an imported record this plane cannot prove is
            // a record it will not hold.
            proof: true,
            filters: ReadFilters {
                event_types: subscription.event_types.clone(),
                ..ReadFilters::default()
            },
        };
        let scope = ReadScope::Tenant {
            zone: subscription.zone.clone(),
            ledger: subscription.ledger.clone(),
        };

        let page = match self.reader.read(&scope, &window) {
            Ok(page) => page,
            Err(ReadError::Expired {
                oldest,
                oldest_sequence,
                requested_sequence,
            }) => {
                // Expected retention behaviour, not corruption — and not something to resume from
                // silently: the gap is recorded, and the cursor moves to the oldest still held so
                // the subscription keeps working with a hole an operator can see.
                warn!(
                    event.name = "events.import_gap",
                    component = COMPONENT,
                    zone = subscription.zone.as_str(),
                    ledger = subscription.ledger.as_str(),
                    oldest_sequence,
                    requested_sequence,
                    "the control plane no longer holds where this plane stood: resuming from the \
                     oldest available, with a gap"
                );
                self.metrics.count(&measure::IMPORT_GAPS, &labels);
                // Recorded and advanced as one step. Advancing alone is what made a history with a
                // hole in it look exactly like one without: the subscription would resume, catch
                // up, and report itself fresh, while every decision after it ranged over fewer
                // occurrences than actually happened.
                if let Err(error) = self.imports.record_gap(
                    &subscription.zone,
                    &subscription.ledger,
                    &oldest,
                    super::imports::Gap {
                        zone: subscription.zone.clone(),
                        ledger: subscription.ledger.clone(),
                        from_sequence: requested_sequence,
                        to_sequence: oldest_sequence,
                        at: permguard_events::index::render_epoch_seconds(
                            std::time::SystemTime::now()
                                .duration_since(std::time::UNIX_EPOCH)
                                .map(|held| held.as_secs() as i64)
                                .unwrap_or_default(),
                        )
                        .unwrap_or_default(),
                        consistency: self.consistency.as_str().to_owned(),
                        resolved: false,
                    },
                ) {
                    return Round::Deferred(error.to_string());
                }

                return Round::Deferred(format!(
                    "the control plane holds from {oldest_sequence} and this plane stood at \
                     {requested_sequence}"
                ));
            }
            Err(error) => return Round::Deferred(error.to_string()),
        };

        // Nothing is imported before everything is verified. A page that fails anywhere leaves the
        // cursor where it was, so the next round asks again rather than skipping over it.
        let mut verified = Vec::with_capacity(page.records.len());
        for (index, held) in page.records.iter().enumerate() {
            if let Err(reason) = self.verify(held, page.inclusion.get(index), &page.proof) {
                warn!(
                    event.name = "events.import_refused",
                    component = COMPONENT,
                    zone = subscription.zone.as_str(),
                    ledger = subscription.ledger.as_str(),
                    reason = reason.as_str(),
                    "an imported record could not be verified: quarantined rather than applied"
                );
                self.metrics
                    .count(&measure::IMPORTS, &[("outcome", "quarantined")]);

                return Round::Quarantined {
                    records: page.records.len().saturating_sub(index),
                    reason,
                };
            }
            verified.push(held.clone());
        }

        let mut imported = 0;
        let mut duplicates = 0;
        for record in &verified {
            match self
                .imports
                .absorb(&subscription.zone, &subscription.ledger, record)
            {
                Ok(true) => imported += 1,
                Ok(false) => duplicates += 1,
                Err(error) => return Round::Deferred(error.to_string()),
            }
        }
        // Persisted before the cursor moves: a crash between the two costs a re-read, and a crash
        // the other way round would lose records the cursor claimed to have passed.
        if let Err(error) =
            self.imports
                .advance(&subscription.zone, &subscription.ledger, &page.next)
        {
            return Round::Deferred(error.to_string());
        }

        self.metrics
            .add(&measure::IMPORTED, &labels, imported as f64);
        if imported == 0 && duplicates == 0 {
            return Round::Idle;
        }
        info!(
            event.name = "events.imported",
            component = COMPONENT,
            zone = subscription.zone.as_str(),
            ledger = subscription.ledger.as_str(),
            imported,
            duplicates,
            "history other planes recorded was verified and imported"
        );
        self.metrics.count(&measure::IMPORTS, &[("outcome", "ok")]);

        Round::Imported {
            records: imported,
            duplicates,
        }
    }

    /// Everything an imported record must be, before it is written.
    fn verify(
        &self,
        record: &Value,
        inclusion: Option<&Value>,
        envelopes: &[Value],
    ) -> Result<(), String> {
        let event_type = record
            .get("event_type")
            .and_then(Value::as_str)
            .ok_or_else(|| "a record with no `event_type`".to_owned())?;
        if !self.accepted_types.iter().any(|held| held == event_type) {
            return Err(format!(
                "`{event_type}` is not a type this build registers a validator for"
            ));
        }

        // The digest of the record as it arrived, against the leaf its path claims.
        let digest = record::digest_of(record).map_err(|error| error.to_string())?;
        let path = inclusion.ok_or_else(|| {
            "the control plane returned no inclusion path for this record".to_owned()
        })?;
        let leaf = path
            .get("leaf")
            .and_then(Value::as_str)
            .ok_or_else(|| "an inclusion path with no leaf".to_owned())?;
        if leaf != digest {
            return Err(
                "the inclusion path is for a different record than the one it came with".to_owned(),
            );
        }
        let root = path
            .get("root")
            .and_then(Value::as_str)
            .ok_or_else(|| "an inclusion path with no root".to_owned())?;
        let steps: Vec<permguard_decisions::merkle::Step> = path
            .get("path")
            .cloned()
            .and_then(|held| serde_json::from_value(held).ok())
            .ok_or_else(|| "an inclusion path with no steps".to_owned())?;
        if permguard_events::merkle_of(leaf, &steps) != root {
            return Err("the inclusion path does not reach the root it names".to_owned());
        }

        // And that root must be one a producer this plane trusts actually signed.
        let signed = envelopes.iter().find_map(|envelope| {
            let held: Signed = serde_json::from_value(envelope.clone()).ok()?;
            let verified = held.verify(&self.keys).ok()?;
            (verified.merkle_root == root).then_some(verified)
        });
        let Some(envelope) = signed else {
            return Err(format!(
                "no envelope signed by a producer this plane trusts attests the root {root}"
            ));
        };

        // The tenant binding: a record whose stream names another ledger is a record that reached
        // the wrong view, and importing it would put one tenant's history inside another's.
        let stream: permguard_events::Stream = record
            .get("stream")
            .cloned()
            .and_then(|held| serde_json::from_value(held).ok())
            .ok_or_else(|| "a record with no stream".to_owned())?;
        if stream != envelope.stream {
            return Err(
                "the record's stream is not the one the envelope that attests it names".to_owned(),
            );
        }

        Ok(())
    }
}

/// The origin positions a page carried, for a caller that wants to report them.
pub fn origins(records: &[Value]) -> BTreeSet<(String, String, String, u64)> {
    records
        .iter()
        .filter_map(|record| {
            let stream = record.get("stream")?.get("producer")?;

            Some((
                stream.get("class")?.as_str()?.to_owned(),
                stream.get("id")?.as_str()?.to_owned(),
                stream.get("instance")?.as_str()?.to_owned(),
                record.get("seq")?.as_u64()?,
            ))
        })
        .collect()
}
