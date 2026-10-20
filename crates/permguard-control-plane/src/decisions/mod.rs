// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The decision-log store, as specified in `docs/decision-logs.md`.
//!
//! ```text
//! legacy producers ──► ingest ──► producer streams (verbatim, append-only)
//! the Host's consumer of `data/decisions` ──► the tenant view, by concrete ids
//!                              │
//!                              ▼  read from an offset
//!                        SIEM, data lake, an application, the CLI
//! ```
//!
//! Since WP-6.3a the tenant view reads the Host's consumer alone, by the ledger's concrete ids;
//! this store keeps the legacy producers' streams, read whole by `pdp` and `instance`.
//!
//! | Module | What it does |
//! | --- | --- |
//! | [`configuration`] | what this plane publishes about the decision log interface |
//! | [`ingest`] | verifies a batch and answers with a contiguous durable sequence |
//! | [`http`] | the shipping and reading routes |
//! | [`grpc`] | the same contract, over the other transport |
//! | [`store`] | keeps the legacy producers' records verbatim, per producer stream |
//! | [`offset`] | where a consumer stands, opaque and bound to its scope |
//! | [`read`] | serving a page of records, and the proofs that go with them |
//! | [`retention`] | how long they are kept, and what leaving looks like |
//! | [`measure`] | what the store reports about itself |
//!
//! **One writer, many readers.** The store keeps no per-consumer state, so any
//! number of readers coexist and none can back-pressure a producer. Exporters
//! — OTLP, object storage, a broker, a webhook — are *readers*, configured,
//! never a branch in the write path.

pub mod configuration;
pub mod cursorkey;
pub mod grpc;
pub mod http;
pub mod ingest;
pub mod measure;
pub mod offset;
pub mod read;
pub mod retention;
pub mod store;

pub use ingest::{Accepted, Refused};
pub use offset::{Offset, OffsetError};
pub use store::{DecisionStore, Scope};
