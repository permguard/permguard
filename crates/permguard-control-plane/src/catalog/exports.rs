// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! Ledger and zone export (WP-7.10, `1-architecture/8-architecture-storage-operations.md`
//! migration and upgrade): the archive of a zone's ledgers, or of one.
//!
//! ```text
//! archive  {1 manifest, 2 bundle}       the manifest's COSE_Sign1 bytes, the bundle's bytes
//! bundle   [{1 ledger, 2 kind, 3 bytes, 4? ref}]
//!            kind 1 object          its canonical bytes, uncompressed, every object every ref
//!                                   of the ledger reaches, in digest order
//!            kind 2 head statement  the COSE_Sign1 cached for ref `4`, as stored
//! ```
//!
//! The manifest ([`permguard_host::exports::Manifest`]) is signed by the Host under
//! `host.operations`; this plane hands it the fields. An archive is answered in one message: one
//! that would pass the transport's ceiling is refused before anything is signed.

use std::path::PathBuf;

use permguard_core::authz::{Actor, operations};
use permguard_core::catalog::Selector;
use permguard_core::{ApiError, ErrorClass, Ledger, Zone, codes};
use permguard_host::composition::{LedgerExportV1, Signer};
use permguard_host::exports::{self, ExportedLedger, ExportedRef, Manifest};
use permguard_objects::cbor::{self, Value};

use super::CatalogFacade;
use crate::store::FileObjectStore;
use crate::wire::Refusal;

/// A bundle entry holding an object.
pub const OBJECT: i64 = 1;
/// A bundle entry holding a head statement.
pub const STATEMENT: i64 = 2;

/// The bytes a bundle entry's own framing takes beyond its payload, at most: the map, its labels
/// and the byte string's head.
const ENTRY_FRAMING: usize = 32;

/// What an export needs beyond the catalog.
pub(crate) struct Exports {
    /// `<volume>/data/zones`: every ledger's store.
    zones_root: PathBuf,
    /// The capability to have the Host sign a manifest under `host.operations`.
    signer: Signer<LedgerExportV1>,
    /// This Host's id, the source authority every manifest names.
    authority: [u8; 16],
    /// The most bytes an archive takes: what one message carries. An export holds a few times
    /// that in memory while it is built.
    max_bytes: usize,
    /// One export at a time: the memory bound is per export.
    running: std::sync::Mutex<()>,
}

impl Exports {
    pub(crate) fn new(
        zones_root: PathBuf,
        signer: Signer<LedgerExportV1>,
        authority: [u8; 16],
        max_bytes: usize,
    ) -> Self {
        Self {
            zones_root,
            signer,
            authority,
            max_bytes,
            running: std::sync::Mutex::new(()),
        }
    }
}

/// An archive and what its manifest binds.
#[derive(Debug)]
pub(crate) struct Exported {
    pub(crate) archive: Vec<u8>,
    pub(crate) manifest: Manifest,
}

/// An export as both transports answer it: the archive, base64url, and what its manifest binds.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub(crate) struct ExportView {
    pub(crate) archive: String,
    pub(crate) zone_id: String,
    pub(crate) bundle_digest: String,
    pub(crate) bundle_bytes: u64,
    /// When the export was made, seconds since the Unix epoch.
    pub(crate) exported_at: u64,
    pub(crate) ledgers: Vec<ExportedLedgerView>,
}

/// One ledger an export holds.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub(crate) struct ExportedLedgerView {
    pub(crate) id: String,
    pub(crate) name: String,
    pub(crate) refs: u64,
    pub(crate) objects: u64,
    pub(crate) statements: u64,
}

impl Exported {
    /// The answer both transports give.
    pub(crate) fn view(&self) -> ExportView {
        use base64::Engine as _;
        ExportView {
            archive: base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&self.archive),
            zone_id: self.manifest.zone_id.clone(),
            bundle_digest: self.manifest.bundle_digest.to_string(),
            bundle_bytes: self.manifest.bundle_bytes,
            exported_at: self.manifest.exported_at,
            ledgers: self
                .manifest
                .ledgers
                .iter()
                .map(|ledger| ExportedLedgerView {
                    id: ledger.id.clone(),
                    name: ledger.name.clone(),
                    refs: ledger.refs.len() as u64,
                    objects: ledger.objects,
                    statements: ledger.statements,
                })
                .collect(),
        }
    }
}

fn unavailable(detail: impl Into<String>) -> ApiError {
    ApiError::new(ErrorClass::Unavailable, codes::common::UNAVAILABLE, detail)
}

fn internal(detail: impl std::fmt::Display) -> ApiError {
    ApiError::new(
        ErrorClass::Internal,
        codes::common::INTERNAL,
        detail.to_string(),
    )
}

impl CatalogFacade {
    fn exports(&self) -> Result<&Exports, Refusal> {
        self.exports.as_deref().ok_or_else(|| {
            unavailable(
                "exports are not served: the Host composes no `host.operations` signer for this \
                 plane",
            )
            .into()
        })
    }
}

/// Exports one ledger under `catalog.read` on it (WP-7.10): the archive of a zone holding that
/// ledger alone.
#[tracing::instrument(name = "ledger.export", skip_all)]
pub(crate) async fn ledger(
    facade: &CatalogFacade,
    actor: &Actor,
    zone: &str,
    ledger: &str,
) -> Result<Exported, Refusal> {
    let (zone, ledger) = facade.resolve_ledger(actor, operations::CATALOG_READ, zone, ledger)?;
    let exported = facade
        .exports()?
        .archive(&zone, std::slice::from_ref(&ledger))?;
    facade
        .record(
            "ledger.exported",
            &super::target::ledger(&zone.id, &ledger.id),
        )
        .await?;
    Ok(exported)
}

/// Exports every ledger of a zone under `catalog.read` on the zone itself and on every ledger of
/// it (WP-7.10): one the caller may not read refuses the export, never trims it, so an archive of
/// a zone is always the whole zone.
#[tracing::instrument(name = "zone.export", skip_all)]
pub(crate) async fn zone(
    facade: &CatalogFacade,
    actor: &Actor,
    zone: &str,
) -> Result<Exported, Refusal> {
    let zone = facade.resolve_zone(actor, operations::CATALOG_READ, zone)?;
    let ledgers = facade
        .catalog
        .list_ledgers(&Selector::Id(zone.id.clone()))
        .map_err(super::api_error)?;
    for ledger in &ledgers {
        facade.authorize(
            actor,
            operations::CATALOG_READ,
            &super::ledger_resource(&zone.id, &ledger.id),
        )?;
    }
    let exported = facade.exports()?.archive(&zone, &ledgers)?;
    facade
        .record("zone.exported", &super::target::zone(&zone.id))
        .await?;
    Ok(exported)
}

impl Exports {
    /// The archive of `ledgers` of `zone`, its manifest signed now, by the Host's clock.
    pub(crate) fn archive(&self, zone: &Zone, ledgers: &[Ledger]) -> Result<Exported, ApiError> {
        let _running = self
            .running
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let exported_at = u64::try_from(self.signer.signing_time())
            .map_err(|_| unavailable("the Host's clock reads before the epoch"))?;
        // Every ledger's refs, read once: the manifest names them and the bundle carries what they
        // reach, so a push meanwhile cannot make the two disagree.
        let mut stores = Vec::new();
        let mut exported = Vec::new();
        for ledger in ledgers {
            let store = FileObjectStore::new(
                self.zones_root
                    .join(&zone.id)
                    .join("ledgers")
                    .join(&ledger.id),
            );
            let refs = store.list_refs().map_err(internal)?;
            exported.push(ExportedLedger {
                id: ledger.id.clone(),
                name: ledger.name.clone(),
                default_ref: ledger.default_ref.clone(),
                refs: refs
                    .into_iter()
                    .map(|(name, state)| ExportedRef {
                        name,
                        counter: state.counter,
                        head: state.head,
                    })
                    .collect(),
                objects: 0,
                statements: 0,
            });
            stores.push(store);
        }
        // The manifest's own size, bounded before any object is read.
        let skeleton = Manifest {
            host_id: self.authority,
            exported_at,
            zone_id: zone.id.clone(),
            zone_name: zone.name.clone(),
            ledgers: exported.clone(),
            bundle_digest: exports::bundle_digest(&[]),
            bundle_bytes: u64::MAX >> 2,
        }
        .encode()
        .map_err(|error| unavailable(format!("the export manifest cannot be made: {error}")))?;
        let mut held = self.within(0, skeleton.len() + 4 * ENTRY_FRAMING)?;
        let mut entries = Vec::new();
        for (index, (store, ledger)) in stores.iter().zip(exported.iter_mut()).enumerate() {
            let closure =
                crate::gc::reachable_from(store, ledger.refs.iter().map(|held| held.head.clone()))
                    .map_err(internal)?;
            let at = Value::Int(i64::try_from(index).map_err(internal)?);
            for digest in &closure {
                let bytes = store.get_object(digest).map_err(internal)?.ok_or_else(|| {
                    internal(format!("the object {digest} is reached and missing"))
                })?;
                held = self.within(held, bytes.len() + ENTRY_FRAMING)?;
                entries.push(Value::Map(vec![
                    (Value::Int(1), at.clone()),
                    (Value::Int(2), Value::Int(OBJECT)),
                    (Value::Int(3), Value::Bytes(bytes)),
                ]));
            }
            // A head statement is a cache the store replaces with its ref: one read after the refs
            // may attest a later head, which an importer finds against the manifest's.
            let mut statements = 0u64;
            for named in &ledger.refs {
                if let Some(envelope) = store.read_signature(&named.name).map_err(internal)? {
                    held = self.within(held, envelope.len() + named.name.len() + ENTRY_FRAMING)?;
                    statements += 1;
                    entries.push(Value::Map(vec![
                        (Value::Int(1), at.clone()),
                        (Value::Int(2), Value::Int(STATEMENT)),
                        (Value::Int(3), Value::Bytes(envelope)),
                        (Value::Int(4), Value::Text(named.name.clone())),
                    ]));
                }
            }
            ledger.objects = closure.len() as u64;
            ledger.statements = statements;
        }
        let bundle = cbor::encode(&Value::Array(entries)).map_err(internal)?;
        let manifest = Manifest {
            host_id: self.authority,
            exported_at,
            zone_id: zone.id.clone(),
            zone_name: zone.name.clone(),
            ledgers: exported,
            bundle_digest: exports::bundle_digest(&bundle),
            bundle_bytes: bundle.len() as u64,
        };
        let envelope = self
            .signer
            .sign(&manifest)
            .map_err(|error| unavailable(format!("the export manifest was not signed: {error}")))?;
        let archive = cbor::encode(&Value::Map(vec![
            (Value::Int(1), Value::Bytes(envelope)),
            (Value::Int(2), Value::Bytes(bundle)),
        ]))
        .map_err(internal)?;
        // The budget counted the manifest and every entry's framing: this cannot pass it.
        if archive.len() > self.max_bytes {
            return Err(self.too_large(archive.len(), "it was signed and is not answered"));
        }
        Ok(Exported { archive, manifest })
    }

    /// `held` grown by `more`, refused once it passes what one message carries.
    fn within(&self, held: usize, more: usize) -> Result<usize, ApiError> {
        let held = held.saturating_add(more);
        if held > self.max_bytes {
            return Err(self.too_large(held, "nothing was signed"));
        }
        Ok(held)
    }

    fn too_large(&self, bytes: usize, outcome: &str) -> ApiError {
        unavailable(format!(
            "the archive would take more than {bytes} bytes, past the {} one message carries, so \
             {outcome}: export the ledgers one at a time; a paged export is not served yet",
            self.max_bytes
        ))
    }
}

#[cfg(test)]
pub(crate) mod tests {
    #![allow(clippy::expect_used)]

    use std::collections::BTreeMap;
    use std::sync::Arc;

    use permguard_core::catalog::Catalog as _;
    use permguard_core::domains::protected;
    use permguard_objects::Digest;
    use permguard_objects::cose::Sign1;
    use permguard_objects::object::{Blob, Commit, Kind, Tree, TreeEntry};
    use permguard_std::catalog::FileCatalog;

    use super::*;

    pub(crate) struct Fixture {
        pub(crate) catalog: Arc<FileCatalog>,
        pub(crate) exports: Exports,
        pub(crate) zone: Zone,
        pub(crate) ledger: Ledger,
        ring: crate::handles::TestRing,
        reached: std::collections::BTreeSet<Digest>,
        orphan: Digest,
        head: Digest,
    }

    /// The digests a bundle's objects of ledger `index` must hold: what [`Exports::archive`] wrote.
    fn objects_of(
        bundle: &[u8],
        index: i64,
    ) -> std::collections::BTreeSet<permguard_objects::Digest> {
        let Ok(Value::Array(entries)) = cbor::decode_canonical(bundle) else {
            return std::collections::BTreeSet::new();
        };
        entries
            .into_iter()
            .filter_map(|entry| match entry {
                Value::Map(pairs) => {
                    let field = |label: i64| {
                        pairs
                            .iter()
                            .find(|(key, _)| *key == Value::Int(label))
                            .map(|(_, value)| value.clone())
                    };
                    match (field(1), field(2), field(3)) {
                        (
                            Some(Value::Int(at)),
                            Some(Value::Int(OBJECT)),
                            Some(Value::Bytes(bytes)),
                        ) if at == index => Some(permguard_objects::Digest::compute(&bytes)),
                        _ => None,
                    }
                }
                _ => None,
            })
            .collect()
    }

    fn blob(text: &str) -> Vec<u8> {
        Blob {
            media_type: "application/vnd.permguard.policy.cedar".to_owned(),
            data: text.as_bytes().to_vec(),
        }
        .encode()
        .expect("a blob")
    }

    pub(crate) fn fixture(tag: &str, max_bytes: usize) -> Fixture {
        let root = std::env::temp_dir().join(format!(
            "permguard-export-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        let catalog = Arc::new(FileCatalog::new(root.join("zones")));
        let zone = catalog.create_zone("delivery").expect("a zone");
        let ledger = catalog
            .create_ledger(&Selector::Id(zone.id.clone()), "release")
            .expect("a ledger");
        let store = FileObjectStore::new(
            root.join("zones")
                .join(&zone.id)
                .join("ledgers")
                .join(&ledger.id),
        );
        let policy = store
            .put_object(&blob("permit (principal, action, resource);"))
            .expect("stored")
            .0;
        let manifest = store.put_object(&blob("the manifest")).expect("stored").0;
        let tree = store
            .put_object(
                &Tree {
                    entries: vec![TreeEntry {
                        kind: Kind::Blob,
                        digest: policy.clone(),
                        name: "rules.cedar".to_owned(),
                        annotations: BTreeMap::new(),
                    }],
                }
                .encode()
                .expect("a tree"),
            )
            .expect("stored")
            .0;
        let head = store
            .put_object(
                &Commit {
                    tree: tree.clone(),
                    manifest: manifest.clone(),
                    predecessors: Vec::new(),
                    author: "test".to_owned(),
                    author_at: 1,
                    message: "the first".to_owned(),
                }
                .encode()
                .expect("a commit"),
            )
            .expect("stored")
            .0;
        let orphan = store
            .put_object(&blob("no ref reaches this"))
            .expect("stored")
            .0;
        let mutations = crate::store::testing::offline_ref_mutations(&root.join("volume"))
            .expect("the transaction");
        crate::store::testing::update_ref(&mutations, &store, "main", None, &head)
            .expect("the ref");
        store
            .write_signature("main", b"a head statement")
            .expect("the statement");
        let ring = crate::handles::ring_for_tests(&root.join("ring"));
        Fixture {
            catalog,
            exports: Exports::new(
                root.join("zones"),
                crate::handles::export_signer_for_tests(Arc::clone(&ring)),
                [7; 16],
                max_bytes,
            ),
            zone,
            ledger,
            ring,
            reached: [policy, manifest, tree, head.clone()].into_iter().collect(),
            orphan,
            head,
        }
    }

    /// The archive's manifest and bundle.
    fn parts(archive: &[u8]) -> (Vec<u8>, Vec<u8>) {
        let Value::Map(pairs) = cbor::decode_canonical(archive).expect("canonical") else {
            panic!("a map");
        };
        match pairs.as_slice() {
            [
                (Value::Int(1), Value::Bytes(manifest)),
                (Value::Int(2), Value::Bytes(bundle)),
            ] => (manifest.clone(), bundle.clone()),
            other => panic!("not an archive: {other:?}"),
        }
    }

    /// WP-7.10: an export carries every object a ref reaches and no other, every head statement
    /// as stored, and a manifest the Host signed under `host.operations` binding the source, the
    /// refs, the counts and the bundle's digest.
    #[test]
    fn an_export_binds_the_closure_the_refs_and_the_bundle() {
        let fixture = fixture("closure", 1 << 20);
        let exported = fixture
            .exports
            .archive(&fixture.zone, std::slice::from_ref(&fixture.ledger))
            .expect("exported");
        let (envelope, bundle) = parts(&exported.archive);

        let jwk = fixture
            .ring
            .public_keys()
            .expect("the ring's keys")
            .into_iter()
            .next()
            .expect("a key");
        let (suite, public) = permguard_host::keys::bundle::public_of(&jwk).expect("a public key");
        let payload = Sign1::decode(&envelope)
            .expect("COSE_Sign1")
            .verify(suite, &public, protected::LEDGER_EXPORT)
            .expect("signed under the ring")
            .to_vec();
        let manifest = Manifest::decode(&payload).expect("a manifest");
        assert_eq!(manifest, exported.manifest);
        assert_eq!(manifest.host_id, [7; 16]);
        assert!(manifest.exported_at > 1_700_000_000, "the Host's clock");
        assert_eq!(
            (manifest.zone_id.as_str(), manifest.zone_name.as_str()),
            (fixture.zone.id.as_str(), "delivery")
        );
        assert_eq!(manifest.bundle_digest, exports::bundle_digest(&bundle));
        assert_eq!(manifest.bundle_bytes, bundle.len() as u64);
        let ledger = &manifest.ledgers[0];
        assert_eq!(
            (
                ledger.id.as_str(),
                ledger.name.as_str(),
                ledger.default_ref.as_str()
            ),
            (fixture.ledger.id.as_str(), "release", "main")
        );
        assert_eq!(
            ledger.refs,
            vec![ExportedRef {
                name: "main".to_owned(),
                counter: 1,
                head: fixture.head.clone(),
            }]
        );
        assert_eq!((ledger.objects, ledger.statements), (4, 1));

        let carried = objects_of(&bundle, 0);
        assert_eq!(carried, fixture.reached);
        assert!(!carried.contains(&fixture.orphan), "nothing no ref reaches");
        let Value::Array(entries) = cbor::decode_canonical(&bundle).expect("canonical") else {
            panic!("an array");
        };
        assert!(entries.contains(&Value::Map(vec![
            (Value::Int(1), Value::Int(0)),
            (Value::Int(2), Value::Int(STATEMENT)),
            (Value::Int(3), Value::Bytes(b"a head statement".to_vec())),
            (Value::Int(4), Value::Text("main".to_owned())),
        ])));
    }

    /// WP-7.10: an archive that would pass what one message carries is refused, never cut.
    #[test]
    fn an_export_past_one_message_is_refused() {
        let fixture = fixture("large", 64);
        let refused = fixture
            .exports
            .archive(&fixture.zone, std::slice::from_ref(&fixture.ledger))
            .expect_err("too large");
        assert_eq!(refused.class(), ErrorClass::Unavailable);
        assert!(
            refused
                .disclosed_message(permguard_core::Disclosure::Full)
                .contains("nothing was signed"),
            "{refused:?}"
        );
    }
}
