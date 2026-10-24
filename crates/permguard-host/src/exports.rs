// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! Ledger and zone export manifests (WP-7.10, `1-architecture/8-architecture-storage-operations.md`
//! migration and upgrade).
//!
//! An export is an archive of one zone's ledgers: the bundle carries every object, ref and head
//! statement byte for byte, and the manifest, a COSE_Sign1 `permguard.ledger.export.v1` under
//! `host.operations`, binds the source authority, what each ledger held and the bundle's digest.
//! The manifest is the Host's: a Plane hands it the fields and the Host writes the signing input
//! ([`crate::composition::LedgerExportV1`]), as no Plane is handed `host.operations`.
//!
//! ```text
//! manifest {1 v: 1, 2 host_id, 3 exported_at, 4 zone {1 id, 2 name},
//!           5 ledgers [{1 id, 2 name, 3 default_ref, 4 refs [{1 name, 2 counter, 3 head}],
//!                       5 objects, 6 statements}],
//!           6 bundle_digest, 7 bundle_bytes}
//! ```
//!
//! The bundle digest is SHA-256 over `permguard.ledger.export.bundle.v1\n` and the bundle's
//! bytes. An importer trusts a manifest through the source Host's keys bundle and identity pin,
//! never through anything the archive carries ([`verify`]).

use std::collections::BTreeMap;

use permguard_core::domains::{digest, protected};
use permguard_objects::Digest;
use permguard_objects::cbor::{self, Value};
use sha2::{Digest as _, Sha256};

/// The most bytes a manifest takes.
pub const MAX_MANIFEST_BYTES: usize = 1024 * 1024;
/// The longest identifier, name or ref name a manifest carries.
const MAX_TEXT_BYTES: usize = 1024;
/// The record version this build writes and reads.
const VERSION: i64 = 1;

/// A ref as the export found it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExportedRef {
    pub name: String,
    /// Its monotonic counter.
    pub counter: u64,
    pub head: Digest,
}

/// A ledger as the export found it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExportedLedger {
    /// Its id at the source, kept: the authority-qualified identifier.
    pub id: String,
    pub name: String,
    pub default_ref: String,
    pub refs: Vec<ExportedRef>,
    /// How many objects of its closure the bundle carries.
    pub objects: u64,
    /// How many head statements the bundle carries.
    pub statements: u64,
}

/// What an export binds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Manifest {
    /// The source authority: the Host that held the ledgers.
    pub host_id: [u8; 16],
    /// When the export was made, seconds.
    pub exported_at: u64,
    pub zone_id: String,
    pub zone_name: String,
    pub ledgers: Vec<ExportedLedger>,
    /// SHA-256 of the bundle under its domain ([`bundle_digest`]).
    pub bundle_digest: Digest,
    pub bundle_bytes: u64,
}

/// The digest a manifest binds of `bundle`.
pub fn bundle_digest(bundle: &[u8]) -> Digest {
    let mut hasher = Sha256::new();
    hasher.update(digest::LEDGER_EXPORT_BUNDLE.as_bytes());
    hasher.update(bundle);
    Digest::from_raw(hasher.finalize().into())
}

fn uint(value: u64, what: &str) -> Result<Value, String> {
    i64::try_from(value)
        .map(Value::Int)
        .map_err(|_| format!("{what} is out of range"))
}

fn text(value: &str, what: &str) -> Result<Value, String> {
    if value.is_empty() || value.len() > MAX_TEXT_BYTES {
        return Err(format!("{what} takes 1 to {MAX_TEXT_BYTES} bytes"));
    }
    Ok(Value::Text(value.to_owned()))
}

/// A closed map's fields by label, every label in `1..=last`, each once.
struct Fields {
    what: String,
    held: BTreeMap<i64, Value>,
}

impl Fields {
    fn of(value: Value, last: i64, what: &str) -> Result<Self, String> {
        let Value::Map(pairs) = value else {
            return Err(format!("{what} is a map"));
        };
        let mut held = BTreeMap::new();
        for (key, value) in pairs {
            match key {
                Value::Int(label) if (1..=last).contains(&label) => {
                    if held.insert(label, value).is_some() {
                        return Err(format!("{what} holds label {label} twice"));
                    }
                }
                _ => return Err(format!("{what} holds an unknown label")),
            }
        }
        Ok(Self {
            what: what.to_owned(),
            held,
        })
    }

    fn take(&mut self, label: i64, field: &str) -> Result<Value, String> {
        self.held
            .remove(&label)
            .ok_or_else(|| format!("{} names no {field}", self.what))
    }

    fn uint(&mut self, label: i64, field: &str) -> Result<u64, String> {
        match self.take(label, field)? {
            Value::Int(value) if value >= 0 => Ok(value as u64),
            _ => Err(format!("{}'s {field} is an unsigned integer", self.what)),
        }
    }

    fn text(&mut self, label: i64, field: &str) -> Result<String, String> {
        match self.take(label, field)? {
            Value::Text(value) if !value.is_empty() && value.len() <= MAX_TEXT_BYTES => Ok(value),
            _ => Err(format!(
                "{}'s {field} is text of 1 to {MAX_TEXT_BYTES} bytes",
                self.what
            )),
        }
    }

    fn digest(&mut self, label: i64, field: &str) -> Result<Digest, String> {
        match self.take(label, field)? {
            Value::Text(value) => {
                Digest::parse(&value).map_err(|error| format!("{}'s {field}: {error}", self.what))
            }
            _ => Err(format!("{}'s {field} is a digest", self.what)),
        }
    }

    fn array(&mut self, label: i64, field: &str) -> Result<Vec<Value>, String> {
        match self.take(label, field)? {
            Value::Array(values) => Ok(values),
            _ => Err(format!("{}'s {field} is an array", self.what)),
        }
    }
}

impl Manifest {
    /// The canonical bytes.
    pub fn encode(&self) -> Result<Vec<u8>, String> {
        let mut ledgers = Vec::new();
        for ledger in &self.ledgers {
            let mut refs = Vec::new();
            for held in &ledger.refs {
                refs.push(Value::Map(vec![
                    (Value::Int(1), text(&held.name, "a ref's name")?),
                    (Value::Int(2), uint(held.counter, "a ref's counter")?),
                    (Value::Int(3), Value::Text(held.head.to_string())),
                ]));
            }
            ledgers.push(Value::Map(vec![
                (Value::Int(1), text(&ledger.id, "a ledger's id")?),
                (Value::Int(2), text(&ledger.name, "a ledger's name")?),
                (
                    Value::Int(3),
                    text(&ledger.default_ref, "a ledger's default ref")?,
                ),
                (Value::Int(4), Value::Array(refs)),
                (
                    Value::Int(5),
                    uint(ledger.objects, "a ledger's object count")?,
                ),
                (
                    Value::Int(6),
                    uint(ledger.statements, "a ledger's statement count")?,
                ),
            ]));
        }
        let bytes = cbor::encode(&Value::Map(vec![
            (Value::Int(1), Value::Int(VERSION)),
            (Value::Int(2), Value::Bytes(self.host_id.to_vec())),
            (Value::Int(3), uint(self.exported_at, "the export's time")?),
            (
                Value::Int(4),
                Value::Map(vec![
                    (Value::Int(1), text(&self.zone_id, "the zone's id")?),
                    (Value::Int(2), text(&self.zone_name, "the zone's name")?),
                ]),
            ),
            (Value::Int(5), Value::Array(ledgers)),
            (Value::Int(6), Value::Text(self.bundle_digest.to_string())),
            (Value::Int(7), uint(self.bundle_bytes, "the bundle's size")?),
        ]))
        .map_err(|error| error.to_string())?;
        if bytes.len() > MAX_MANIFEST_BYTES {
            return Err(format!(
                "an export manifest takes at most {MAX_MANIFEST_BYTES} bytes"
            ));
        }
        Ok(bytes)
    }

    // conformance: boundary
    /// Reads the canonical bytes, closed: every map's labels, the version first, no ledger or ref
    /// named twice.
    pub fn decode(bytes: &[u8]) -> Result<Self, String> {
        const WHAT: &str = "an export manifest";
        if bytes.len() > MAX_MANIFEST_BYTES {
            return Err(format!("{WHAT} takes at most {MAX_MANIFEST_BYTES} bytes"));
        }
        let mut fields = Fields::of(
            cbor::decode_canonical(bytes).map_err(|error| format!("{WHAT}: {error}"))?,
            7,
            WHAT,
        )?;
        match fields.take(1, "version")? {
            Value::Int(version) if version == VERSION => {}
            Value::Int(version) => {
                return Err(format!(
                    "{WHAT} of version {version}, which this build does not read"
                ));
            }
            _ => return Err(format!("{WHAT} names no version")),
        }
        let host_id = match fields.take(2, "host")? {
            Value::Bytes(bytes) => <[u8; 16]>::try_from(bytes.as_slice())
                .map_err(|_| format!("{WHAT}'s host is 16 bytes"))?,
            _ => return Err(format!("{WHAT}'s host is 16 bytes")),
        };
        let exported_at = fields.uint(3, "time")?;
        let mut zone = Fields::of(fields.take(4, "zone")?, 2, "an export's zone")?;
        let zone_id = zone.text(1, "id")?;
        let zone_name = zone.text(2, "name")?;
        let mut ledgers: Vec<ExportedLedger> = Vec::new();
        for value in fields.array(5, "ledgers")? {
            let mut ledger = Fields::of(value, 6, "an exported ledger")?;
            let id = ledger.text(1, "id")?;
            let name = ledger.text(2, "name")?;
            let default_ref = ledger.text(3, "default ref")?;
            let mut refs: Vec<ExportedRef> = Vec::new();
            for value in ledger.array(4, "refs")? {
                let mut held = Fields::of(value, 3, "an exported ref")?;
                let exported = ExportedRef {
                    name: held.text(1, "name")?,
                    counter: held.uint(2, "counter")?,
                    head: held.digest(3, "head")?,
                };
                if refs.iter().any(|other| other.name == exported.name) {
                    return Err(format!("{WHAT} names the ref `{}` twice", exported.name));
                }
                refs.push(exported);
            }
            let exported = ExportedLedger {
                id,
                name,
                default_ref,
                refs,
                objects: ledger.uint(5, "object count")?,
                statements: ledger.uint(6, "statement count")?,
            };
            if ledgers
                .iter()
                .any(|other| other.id == exported.id || other.name == exported.name)
            {
                return Err(format!("{WHAT} names the ledger `{}` twice", exported.name));
            }
            ledgers.push(exported);
        }
        Ok(Self {
            host_id,
            exported_at,
            zone_id,
            zone_name,
            ledgers,
            bundle_digest: fields.digest(6, "bundle digest")?,
            bundle_bytes: fields.uint(7, "bundle size")?,
        })
    }
}

/// A manifest verified, and the Host its keys bundle names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verified {
    pub manifest: Manifest,
    pub host_id: [u8; 16],
}

/// Verifies the export manifest `envelope` (WP-7.10): the keys bundle the operator kept of the
/// source Host, from that Host's identity `pin`; the manifest under that bundle's
/// `host.operations` key it names, a revoked key refused; the manifest naming that Host. The
/// bundle the manifest binds is the importer's to check against [`bundle_digest`].
pub fn verify(
    envelope: &[u8],
    bundle_manifest: &[u8],
    bundle_items: &[Vec<u8>],
    pin: &str,
) -> Result<Verified, String> {
    if envelope.len() > MAX_MANIFEST_BYTES + 64 * 1024 {
        return Err(format!(
            "an export manifest takes at most {MAX_MANIFEST_BYTES} bytes"
        ));
    }
    let verified = crate::keys::bundle::verify(bundle_manifest, bundle_items, pin, "host")
        .map_err(|error| format!("the verification bundle: {error}"))?;
    let payload = crate::operations::backup::operations_payload(
        &verified,
        envelope,
        protected::LEDGER_EXPORT,
        "export the bundle from the source Host after the export",
    )?;
    let manifest = Manifest::decode(&payload)?;
    if manifest.host_id != verified.identity.host_id {
        return Err("the manifest names another Host than the bundle".to_owned());
    }
    Ok(Verified {
        host_id: verified.identity.host_id,
        manifest,
    })
}

#[cfg(test)]
mod tests;
