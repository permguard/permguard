// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The decision-log store, as specified in `docs/decision-logs.md`.
//!
//! ```text
//! data planes ──► ingest ──► segments (verbatim, append-only)
//!                              │
//!                              ├─► per-(zone, ledger) views
//!                              │
//!                              ▼  read from an offset
//!                        SIEM, data lake, an application, the CLI
//! ```
//!
//! | Module | What it does |
//! | --- | --- |
//! | [`ingest`] | verifies a batch and answers with a contiguous durable sequence |
//! | [`http`] | the shipping and reading routes |
//! | [`grpc`] | the same contract, over the other transport |
//! | [`store`] | keeps records verbatim, and partitions them per tenant |
//! | [`offset`] | where a consumer stands, opaque and bound to its scope |
//! | [`read`] | serving a page of records, and the proofs that go with them |
//! | [`retention`] | how long they are kept, and what leaving looks like |
//! | [`measure`] | what the store reports about itself |
//!
//! **One writer, many readers.** The store keeps no per-consumer state, so any
//! number of readers coexist and none can back-pressure a producer. Exporters
//! — OTLP, object storage, a broker, a webhook — are *readers*, configured,
//! never a branch in the write path.

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
