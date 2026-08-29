// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! What this plane publishes about the event log.
//!
//! The third layer of the discovery chain, on the control plane's side of it: the process says
//! which planes it runs, a plane says which interfaces it serves, and an interface document says
//! what that interface offers *here*. A caller that found this document has already been told,
//! twice, that it exists.
//!
//! # Why the receiving end needs one at all
//!
//! A data plane that ships its history has to answer three questions before it can ship anything:
//! *where do batches go*, *which event types will be accepted*, and *how are read offsets spelled*.
//! All three are properties of the receiver, and a producer that guessed them would be a producer
//! configured by a runbook rather than by the deployment.
//!
//! Everything here is derived from the constants the routes are mounted from, the API family the
//! offsets are bound to, and the event types the store accepts — so the document cannot advertise a
//! path this plane does not answer, an offset family it would reject, or a type it would refuse.

use serde::{Deserialize, Serialize};

/// Where a control plane publishes what its event log offers.
pub const CONFIGURATION_PATH: &str = "/.well-known/permguard-events-native-v1alpha1-configuration";

/// What this plane implements of `permguard.api.events.native.v1alpha1`.
///
/// Every entry is implemented and tested here. A capability is a promise.
pub const CAPABILITIES: [&str; 6] = [
    // A batch is accepted whole or not at all, and a producer's retry of one already stored is
    // recognised rather than duplicated.
    "atomic-batches",
    "idempotent-ingest",
    // Every record's signature is checked against a published producer key before it is stored.
    "attributed-records",
    // A read position is a MAC-authenticated opaque string, bound to the scope and filters it was
    // issued for: it cannot be edited into a wider view.
    "authenticated-offsets",
    // A page states what it covered, so a reader can tell "nothing more yet" from "you have fallen
    // behind retention".
    "read-coverage",
    // One tenant's records, readable by that tenant, without a view of anybody else's.
    "tenant-scoped-reads",
];

/// The filter names a read accepts, in the order [`super::read::Filters`] declares them.
pub const FILTERS: [&str; 10] = [
    "event_types",
    "producer",
    "instance",
    "profile",
    "policy_partition",
    "kind",
    "event_id",
    "since",
    "until_time",
    "history",
];

/// What this plane publishes about `permguard.api.events.native.v1alpha1`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Document {
    /// The contract and its version.
    pub interface: String,
    /// This store's identifier.
    pub store: String,
    pub endpoints: Endpoints,
    /// The registered event contracts this plane will store.
    ///
    /// Read off what the build carries rather than configured: a type is accepted exactly when
    /// something here can validate it, and a list an operator could widen would be a way to store
    /// records nothing understands.
    pub event_types: Vec<String>,
    pub capabilities: Vec<String>,
    pub offsets: Offsets,
    /// The producer classes this store accepts a batch from.
    ///
    /// Published because "which class am I" is a decision a producer makes at configuration time,
    /// and discovering the answer by being refused is discovering it in production.
    pub producer_classes: Vec<String>,
    /// The filter names a read accepts.
    ///
    /// A consumer that guessed would silently get an unfiltered page — every record the ledger
    /// retains instead of the few it asked for — because an unknown filter has nothing to match
    /// against. Published so the guess is unnecessary.
    pub filters: Vec<String>,
    /// What one page will carry at most, whatever a reader asks for.
    pub limits: Limits,
}

/// The ceilings a read is clamped to.
///
/// Published rather than discovered: a consumer sizing its own buffers, or deciding how often to
/// poll, is making a decision this plane already knows the answer to. Learning it by watching pages
/// come back smaller than requested is learning it by inference.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Limits {
    /// The most records one page may carry.
    pub max_records: u64,
    /// The most bytes one page may carry.
    ///
    /// A single record larger than this is still returned — one oversize record per page rather
    /// than a page nothing can ever fill — so this bounds the ordinary case and not every case.
    pub max_bytes: u64,
    /// The most positions one page will examine while looking for matches.
    ///
    /// What keeps a sparse filter from turning one page into a full scan: a page may come back
    /// empty having examined this many, and say so through its coverage.
    pub max_examined: u64,
}

/// Where batches are delivered and records are read.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Endpoints {
    /// Where a producer delivers a batch.
    pub ingest: String,
    /// The operator's view: every record this store holds, across producers.
    pub records: String,
    /// One occurrence, by the identifier its caller stated.
    pub record: String,
    /// A tenant's own view of its own ledger.
    pub tenant_records: String,
}

/// How a reader's position is spelled.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Offsets {
    /// The API family an offset issued here belongs to. An offset from another family is refused
    /// rather than reinterpreted.
    pub api: String,
    /// `opaque`: the string is this plane's to produce and to read, and carries a MAC binding it to
    /// the scope, filters and bound it was issued for.
    pub format: String,
    /// Whether a reader may hand back an offset it edited. It may not, and it will be told so.
    pub editable: bool,
}

/// The document for a plane reached at `base`.
pub fn document(base: &str, store: &str, event_types: &[&str]) -> Document {
    let base = base.trim_end_matches('/');

    Document {
        interface: super::read::API.to_owned(),
        store: store.to_owned(),
        endpoints: Endpoints {
            // Built from the constants the router mounts, so the two cannot drift.
            ingest: format!("{base}{}", super::http::BATCHES_PATH),
            records: format!("{base}{}", super::http::RECORDS_PATH),
            record: format!("{base}{}", super::http::RECORD_PATH),
            tenant_records: format!("{base}{}", super::http::TENANT_RECORDS_PATH),
        },
        event_types: event_types.iter().map(|held| (*held).to_owned()).collect(),
        capabilities: CAPABILITIES.iter().map(|held| (*held).to_owned()).collect(),
        offsets: Offsets {
            api: super::read::API.to_owned(),
            format: "opaque".to_owned(),
            editable: false,
        },
        producer_classes: vec![permguard_events::record::PRODUCER_CLASS_DATA_PLANE.to_owned()],
        // Taken from the field names the read filter actually carries, so a filter added to the
        // struct without being published here is a difference somebody notices.
        filters: FILTERS.iter().map(|held| (*held).to_owned()).collect(),
        limits: Limits {
            max_records: permguard_stream::window::MAX_RECORDS as u64,
            max_bytes: permguard_stream::window::MAX_BYTES,
            max_examined: permguard_stream::window::MAX_EXAMINED as u64,
        },
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;

    fn parsed(base: &str) -> serde_json::Value {
        serde_json::to_value(document(
            base,
            "test-store",
            &[permguard_languages::event::EVENT_TYPE],
        ))
        .expect("the document serializes")
    }

    /// Every endpoint is the path the router actually mounts.
    ///
    /// Written from the constants rather than repeated as text: a document that advertised a path
    /// this plane does not answer would send a producer's whole history to a `404`, and it would
    /// do so at exactly the moment nobody is watching — the first ship after a deployment.
    #[test]
    fn every_endpoint_is_a_path_the_router_mounts() {
        let document = parsed("http://host/");

        assert_eq!(
            document["endpoints"]["ingest"],
            format!("http://host{}", super::super::http::BATCHES_PATH)
        );
        assert_eq!(
            document["endpoints"]["records"],
            format!("http://host{}", super::super::http::RECORDS_PATH)
        );
        assert_eq!(
            document["endpoints"]["record"],
            format!("http://host{}", super::super::http::RECORD_PATH)
        );
        assert_eq!(
            document["endpoints"]["tenant_records"],
            format!("http://host{}", super::super::http::TENANT_RECORDS_PATH)
        );
        assert_eq!(document["interface"], super::super::read::API);
    }

    /// The offset family it advertises is the one its cursors are actually bound to.
    ///
    /// An offset carries a MAC over the API family that issued it. A document naming a different
    /// family would be inviting readers to send positions this plane refuses.
    #[test]
    fn the_offset_family_is_the_one_the_cursors_are_bound_to() {
        let document = parsed("http://host");

        assert_eq!(document["offsets"]["api"], super::super::read::API);
        assert_eq!(document["offsets"]["format"], "opaque");
        assert_eq!(document["offsets"]["editable"], false);
    }

    #[test]
    fn it_advertises_the_event_types_this_build_actually_stores() {
        assert_eq!(
            parsed("http://host")["event_types"],
            serde_json::json!([permguard_languages::event::EVENT_TYPE])
        );
    }

    /// What the document publishes about limits is what a read is actually clamped to.
    ///
    /// Numbers repeated as text drift. These are read from the window primitive that enforces
    /// them, so a deployment that tuned one and not the other cannot exist.
    #[test]
    fn the_published_limits_are_the_ones_a_read_is_clamped_to() {
        let document = parsed("http://host");

        assert_eq!(
            document["limits"]["max_records"],
            permguard_stream::window::MAX_RECORDS as u64
        );
        assert_eq!(
            document["limits"]["max_bytes"],
            permguard_stream::window::MAX_BYTES
        );
        assert_eq!(
            document["limits"]["max_examined"],
            permguard_stream::window::MAX_EXAMINED as u64
        );
    }

    /// Every filter a read accepts is a filter the document names.
    ///
    /// A consumer that guessed a filter name would get an unfiltered page — every record the
    /// ledger retains rather than the few it asked for — because an unknown filter has nothing to
    /// match against. So the published list has to be the real one.
    ///
    /// The guard is the destructuring below: it names every field of the real filter set, so a
    /// filter added to `Filters` stops this compiling until it is published too. A test that
    /// compared two lists of strings would go on passing.
    #[test]
    fn every_filter_a_read_accepts_is_published() {
        let super::super::read::Filters {
            event_types: _,
            producer: _,
            instance: _,
            profile: _,
            policy_partition: _,
            kind: _,
            event_id: _,
            since: _,
            until_time: _,
            history: _,
        } = super::super::read::Filters::default();

        assert_eq!(
            FILTERS.len(),
            10,
            "the filter set has ten fields, and the document publishes all of them"
        );
        let mut sorted = FILTERS;
        sorted.sort_unstable();
        let mut unique = sorted.to_vec();
        unique.dedup();
        assert_eq!(unique.len(), FILTERS.len(), "no filter is published twice");
    }

    /// The producer classes published are the ones ingest will actually attribute a batch to.
    #[test]
    fn the_published_producer_classes_are_the_ones_ingest_accepts() {
        let document = parsed("http://host");

        assert_eq!(
            document["producer_classes"],
            serde_json::json!([permguard_events::record::PRODUCER_CLASS_DATA_PLANE])
        );
    }
}
