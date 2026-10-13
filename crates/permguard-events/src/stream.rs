// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The event journal as the Host's stream engine registers it (WP-5.1; owner decision of
//! 2026-10-13): its descriptor and its record codec. The journal keeps writing until WP-6.2
//! adopts the engine.

use permguard_core::domains::{digest, protected};
use permguard_host::keys::ring::DATA_ATTEST;
use permguard_host::membership::record::TaskType;
use permguard_stream::engine::{Descriptor, RecordCodec, ResourceShape, Retention};
use serde_json::Value;

/// The stream's name in the Data Plane's declaration.
pub const STREAM: &str = "data/events";

/// The event journal's descriptor, version 1.
pub fn descriptor() -> Descriptor {
    Descriptor {
        plane: "data".to_owned(),
        stream_type: "events".to_owned(),
        version: 1,
        batch_typ: protected::EVENT_BATCH,
        record_domain: digest::EVENT_RECORD,
        codec_version: 1,
        event_types: Vec::new(),
        resource_shape: ResourceShape::Ledger,
        max_record_bytes: 256 * 1024,
        max_batch_records: 1000,
        retention: Retention::History,
        subscription_required: true,
        ring: DATA_ATTEST,
        task: Some(TaskType::EventsShip),
    }
}

/// An event record: canonical JSON (RFC 8785) that [`crate::record::validate`] accepts.
#[derive(Debug, Clone, Copy, Default)]
pub struct Codec;

impl RecordCodec for Codec {
    type Record = Value;

    fn encode(&self, record: &Value) -> Result<Vec<u8>, String> {
        permguard_stream::jcs::canonicalize(record).map_err(|error| error.to_string())
    }

    fn decode(&self, bytes: &[u8]) -> Result<Value, String> {
        let value: Value = serde_json::from_slice(bytes).map_err(|error| error.to_string())?;
        crate::record::validate(&value).map_err(|error| format!("not an event record: {error}"))?;
        Ok(value)
    }
}
