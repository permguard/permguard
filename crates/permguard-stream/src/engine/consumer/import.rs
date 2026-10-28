// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The member Host's `events.import` on its consumer (WP-6.2c2a, owner decisions of 2026-10-19):
//! an origin's batch, as the origin shipped it, ingested into the origin's own run through the
//! same ingest a coordinator admits shipped batches with, under the origin's membership, epoch and
//! pins; and the import's state per ledger, kept beside the runs as `consumer/<sha256(resource)>/
//! IMPORT`.

use permguard_core::authz::Resource;
use permguard_host::composition::{ImportOrigin, Imported, StreamImport};
use permguard_host::membership::import::State;
use permguard_host::storage::format;
use permguard_host::storage::write::{read_view, replace_view};

use super::super::ingest::{Outcome, Shipping};
use super::super::{RecordCodec, StreamError};
use super::{Consumer, child};

/// The import's state of a ledger, beside its producers' directories.
const IMPORT: &str = "IMPORT";

fn wrap(error: StreamError) -> String {
    error.to_string()
}

impl<C: RecordCodec> StreamImport for Consumer<C> {
    fn held(&self, resource: &Resource, origin: &[u8; 16], run: &[u8; 16]) -> Result<u64, String> {
        let key = self.descriptor.key(resource, *origin).map_err(wrap)?;
        Ok(self
            .with_held(&key, *run, false, |held| Ok(held.acked))
            .map_err(wrap)?
            .unwrap_or(0))
    }

    fn import(
        &self,
        resource: &Resource,
        origin: &ImportOrigin<'_>,
        body: &[u8],
    ) -> Result<Imported, String> {
        let canonical = resource.to_string();
        let pins = origin.pins.to_vec();
        let pinned = move |_: &str, _: u64| pins.clone();
        let shipping = Shipping {
            membership_id: origin.membership_id,
            epoch: origin.epoch,
            member: origin.host_id,
            resource: &canonical,
            pins: &pinned,
        };
        let (answer, forked) = self.ingest(&shipping, body).map_err(wrap)?;
        // The run the origin forked in, as its mark keeps it (after the review): a mark another
        // run left answers this one too.
        let key = self
            .descriptor
            .key(resource, origin.host_id)
            .map_err(wrap)?;
        let marked = self.mark(&key).map_err(wrap)?;
        Ok(match answer.outcome {
            Outcome::Ok => Imported::Admitted {
                acked: answer.acked,
            },
            Outcome::OutOfOrder => Imported::OutOfOrder {
                acked: answer.acked,
            },
            Outcome::Gone => Imported::Gone {
                acked: answer.acked,
            },
            Outcome::Fork => Imported::Fork {
                run: marked.as_ref().map_or([0; 16], |mark| mark.run),
                at: marked
                    .map(|mark| mark.at_seq)
                    .or(forked.map(|forked| forked.at_seq))
                    .unwrap_or(0),
            },
            Outcome::Unverifiable | Outcome::Closed => Imported::Unverifiable,
        })
    }

    fn import_state(&self, resource: &Resource) -> Result<Option<State>, String> {
        let component = self
            .descriptor
            .key(resource, [0; 16])
            .map_err(wrap)?
            .resource_component();
        let Some(dir) = child(&self.dir, &component, false).map_err(wrap)? else {
            return Ok(None);
        };
        read_view(&dir, IMPORT, format::VIEW)
            .map_err(|error| error.to_string())?
            .map(|bytes| State::decode(&bytes).map_err(|error| error.to_string()))
            .transpose()
    }

    fn keep_import_state(&self, resource: &Resource, state: &State) -> Result<(), String> {
        let component = self
            .descriptor
            .key(resource, [0; 16])
            .map_err(wrap)?
            .resource_component();
        let dir = child(&self.dir, &component, true)
            .map_err(wrap)?
            .ok_or_else(|| "the ledger's directory is absent".to_owned())?;
        let bytes = state.encode().map_err(|error| error.to_string())?;
        replace_view(&dir, IMPORT, format::VIEW, &bytes).map_err(|error| error.to_string())
    }
}
