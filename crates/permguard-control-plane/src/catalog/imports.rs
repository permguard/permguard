// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! Ledger and zone import (WP-7.10, `1-architecture/8-architecture-storage-operations.md`
//! migration and upgrade): an archive another Host exported, into an existing zone of this one.
//!
//! | Mode       | What lands                                                     | Served                   |
//! | ---------- | -------------------------------------------------------------- | ------------------------ |
//! | `archive`  | the archive verbatim, `<zone>/archives/<id>/{ARCHIVE, RECORD.json}` | never: foreign evidence |
//! | `re-home`  | a new ledger per source ledger, its provenance in its catalog record, the objects | once an operator pushes a head |
//!
//! Before anything is written the archive is verified whole: the manifest from the source Host's
//! keys bundle and identity pin ([`permguard_host::exports::verify`]); the bundle against the
//! manifest's digest and size; every object canonical and named by its digest; the objects of
//! each ledger exactly the closure of its refs' heads; every head statement on a ref the manifest
//! names; the counts the manifest's. Nothing an import writes replaces anything.
//!
//! Head statements are the source's evidence: counted and kept with an archive, never landed by
//! a re-home and never decoded as this Host's authority; the signed bundle digest is what makes
//! their bytes the source's.
//!
//! A re-home of several ledgers checks every name free first, then creates and fills them one by
//! one: a crash, or a ledger of the same name created meanwhile through the catalog, stops it
//! after some, never replacing anything. The same `request_id` resumes it within the replay
//! window, each ledger's create replayed and its objects landed write-once; after it, the
//! ledgers already created are the operator's to delete or keep.

use std::collections::{BTreeMap, BTreeSet};

use permguard_core::authz::{Actor, operations};
use permguard_core::catalog::Selector;
use permguard_core::{ApiError, ErrorClass, Ledger, Provenance, Zone, codes};
use permguard_host::exports::{self, Manifest};
use permguard_host::storage::Dir;
use permguard_host::storage::write::publish_immutable;
use permguard_objects::Digest;
use permguard_objects::cbor::{self, Value};
use permguard_objects::object::{self, Object};
use serde::{Deserialize, Serialize};

use super::exports::{OBJECT, STATEMENT};
use super::{CatalogFacade, zone_resource};
use crate::store::FileObjectStore;
use crate::wire::Refusal;

/// The archive file of an archive kept as foreign evidence.
pub const ARCHIVE: &str = "ARCHIVE";
/// Its record.
pub const RECORD: &str = "RECORD.json";
/// The directory of a zone's archives.
pub const ARCHIVES: &str = "archives";

/// How an archive is imported.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Mode {
    /// Kept verbatim as immutable foreign evidence, never served.
    Archive,
    /// New ledgers under this Host's authority, their provenance recorded.
    ReHome,
}

impl Mode {
    /// The mode `text` names, as the wire spells it.
    pub(crate) fn parse(text: &str) -> Option<Self> {
        match text {
            "archive" => Some(Self::Archive),
            "re-home" => Some(Self::ReHome),
            _ => None,
        }
    }

    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Archive => "archive",
            Self::ReHome => "re-home",
        }
    }
}

/// What an import is handed.
pub(crate) struct Request<'a> {
    pub(crate) mode: Mode,
    /// The archive's name, or the one ledger's of a one-ledger archive re-homed.
    pub(crate) name: Option<&'a str>,
    pub(crate) request_id: &'a str,
    pub(crate) archive: &'a [u8],
    /// The source Host's keys bundle: its manifest and items.
    pub(crate) bundle_manifest: &'a [u8],
    pub(crate) bundle_items: &'a [Vec<u8>],
    /// The source Host's identity pin.
    pub(crate) pin: &'a str,
}

/// An archive verified whole: its manifest, what its bundle carries per ledger, and the digest an
/// import records of it.
#[derive(Debug)]
struct Verified {
    manifest: Manifest,
    manifest_digest: String,
    /// Per ledger, in the manifest's order: its objects by digest.
    objects: Vec<BTreeMap<Digest, Vec<u8>>>,
}

/// What an archive kept as evidence records of itself.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ArchiveRecord {
    pub(crate) id: String,
    pub(crate) name: String,
    /// When it was imported, seconds since the Unix epoch.
    pub(crate) imported_at: u64,
    pub(crate) manifest_digest: String,
    pub(crate) source_host_id: String,
    pub(crate) source_zone_id: String,
    pub(crate) source_zone_name: String,
    pub(crate) ledgers: Vec<ArchivedLedger>,
}

/// One ledger an archive kept as evidence holds, by its source identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ArchivedLedger {
    pub(crate) id: String,
    pub(crate) name: String,
    pub(crate) refs: u64,
    pub(crate) objects: u64,
    pub(crate) statements: u64,
}

/// An import as both transports answer it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct Imported {
    pub(crate) mode: &'static str,
    pub(crate) manifest_digest: String,
    pub(crate) source_host_id: String,
    pub(crate) source_zone_id: String,
    /// The archive kept, for an `archive` import.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) archive: Option<ArchiveRecord>,
    /// The ledgers created, for a `re-home` import.
    pub(crate) ledgers: Vec<Ledger>,
}

fn invalid(detail: impl Into<String>) -> ApiError {
    ApiError::new(
        ErrorClass::Validation,
        codes::common::INVALID_ARGUMENT,
        detail,
    )
}

fn conflict(detail: impl Into<String>) -> ApiError {
    ApiError::new(ErrorClass::Conflict, codes::catalog::NAME_TAKEN, detail)
}

fn internal(detail: impl std::fmt::Display) -> ApiError {
    ApiError::new(
        ErrorClass::Internal,
        codes::common::INTERNAL,
        detail.to_string(),
    )
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// What verifies an archive's manifest envelope: [`permguard_host::exports::verify`] from the
/// source Host's keys bundle and pin, or a test's own key.
pub(crate) type Check<'a> = &'a (dyn Fn(&[u8]) -> Result<exports::Verified, String> + Sync);

/// Imports an archive into `zone` under `catalog.write` and `policy.push` on it (WP-7.10).
#[tracing::instrument(name = "zone.import", skip_all)]
pub(crate) async fn import(
    facade: &CatalogFacade,
    actor: &Actor,
    zone: &str,
    request: Request<'_>,
) -> Result<Imported, Refusal> {
    let check = |envelope: &[u8]| {
        exports::verify(
            envelope,
            request.bundle_manifest,
            request.bundle_items,
            request.pin,
        )
    };
    import_with(facade, actor, zone, &request, &check).await
}

/// [`import`], the manifest verified by `check`.
pub(crate) async fn import_with(
    facade: &CatalogFacade,
    actor: &Actor,
    zone: &str,
    request: &Request<'_>,
    check: Check<'_>,
) -> Result<Imported, Refusal> {
    let zone = facade.resolve_zone(actor, operations::CATALOG_WRITE, zone)?;
    facade.authorize(actor, operations::POLICY_PUSH, &zone_resource(&zone.id))?;
    let exports = facade.exports.as_deref().ok_or_else(|| {
        ApiError::new(
            ErrorClass::Unavailable,
            codes::common::UNAVAILABLE,
            "imports are not served: this plane composes no transfer of ledgers",
        )
    })?;
    let verified = verify(request, check)?;
    let _importing = exports.importing.lock().await;
    let imported = match request.mode {
        Mode::Archive => {
            let record = keep(exports.zones_root(), &zone, request, &verified)?;
            facade
                .record("zone.archive_imported", &super::target::zone(&zone.id))
                .await?;
            Imported {
                mode: Mode::Archive.as_str(),
                manifest_digest: verified.manifest_digest.clone(),
                source_host_id: hex(&verified.manifest.host_id),
                source_zone_id: verified.manifest.zone_id.clone(),
                archive: Some(record),
                ledgers: Vec::new(),
            }
        }
        Mode::ReHome => {
            let ledgers = rehome(
                facade,
                actor,
                exports.zones_root(),
                &zone,
                request,
                &verified,
            )
            .await?;
            Imported {
                mode: Mode::ReHome.as_str(),
                manifest_digest: verified.manifest_digest.clone(),
                source_host_id: hex(&verified.manifest.host_id),
                source_zone_id: verified.manifest.zone_id.clone(),
                archive: None,
                ledgers,
            }
        }
    };
    Ok(imported)
}

/// The archive `request` hands, verified whole before anything is written.
fn verify(request: &Request<'_>, check: Check<'_>) -> Result<Verified, ApiError> {
    let Ok(Value::Map(pairs)) = cbor::decode_canonical(request.archive) else {
        return Err(invalid("the archive is not a canonical CBOR map"));
    };
    let (envelope, bundle) = match pairs.as_slice() {
        [
            (Value::Int(1), Value::Bytes(envelope)),
            (Value::Int(2), Value::Bytes(bundle)),
        ] => (envelope, bundle),
        _ => return Err(invalid("the archive is not `{1 manifest, 2 bundle}`")),
    };
    let verified = check(envelope)
        .map_err(|error| invalid(format!("the archive does not verify: {error}")))?;
    let manifest = verified.manifest;
    if manifest.ledgers.is_empty() {
        return Err(invalid(
            "the archive holds no ledger: there is nothing to import",
        ));
    }
    if exports::bundle_digest(bundle) != manifest.bundle_digest
        || bundle.len() as u64 != manifest.bundle_bytes
    {
        return Err(invalid("the bundle is not the one the manifest binds"));
    }
    let Ok(Value::Array(entries)) = cbor::decode_canonical(bundle) else {
        return Err(invalid("the bundle is not a canonical CBOR array"));
    };
    let mut objects: Vec<BTreeMap<Digest, Vec<u8>>> = vec![BTreeMap::new(); manifest.ledgers.len()];
    let mut statements: Vec<BTreeSet<String>> = vec![BTreeSet::new(); manifest.ledgers.len()];
    for entry in entries {
        let Value::Map(fields) = entry else {
            return Err(invalid("a bundle entry is not a map"));
        };
        let mut index = None;
        let mut kind = None;
        let mut bytes = None;
        let mut named = None;
        for (key, value) in fields {
            match (key, value) {
                (Value::Int(1), Value::Int(at)) if index.is_none() => index = Some(at),
                (Value::Int(2), Value::Int(at)) if kind.is_none() => kind = Some(at),
                (Value::Int(3), Value::Bytes(at)) if bytes.is_none() => bytes = Some(at),
                (Value::Int(4), Value::Text(at)) if named.is_none() => named = Some(at),
                _ => {
                    return Err(invalid(
                        "a bundle entry holds an unknown or malformed label",
                    ));
                }
            }
        }
        let (Some(index), Some(kind), Some(bytes)) = (index, kind, bytes) else {
            return Err(invalid("a bundle entry misses a label"));
        };
        let index = usize::try_from(index)
            .ok()
            .filter(|index| *index < manifest.ledgers.len())
            .ok_or_else(|| invalid("a bundle entry names no ledger of the manifest"))?;
        match (kind, named) {
            (OBJECT, None) => {
                // Canonical or refused: the decoder takes no other encoding.
                object::decode(&bytes)
                    .map_err(|error| invalid(format!("a bundle object: {error}")))?;
                let digest = Digest::compute(&bytes);
                if objects[index].insert(digest.clone(), bytes).is_some() {
                    return Err(invalid(format!("the bundle carries {digest} twice")));
                }
            }
            (STATEMENT, Some(name)) => {
                if !manifest.ledgers[index]
                    .refs
                    .iter()
                    .any(|held| held.name == name)
                {
                    return Err(invalid(format!(
                        "a head statement attests `{name}`, which the manifest does not name"
                    )));
                }
                if !statements[index].insert(name.clone()) {
                    return Err(invalid(format!("the bundle attests `{name}` twice")));
                }
            }
            _ => return Err(invalid("a bundle entry is of no known kind")),
        }
    }
    for (index, ledger) in manifest.ledgers.iter().enumerate() {
        for held in &ledger.refs {
            permguard_objects::grammar::validate_ref_name(&held.name)
                .map_err(|error| invalid(format!("the ref `{}`: {error}", held.name)))?;
        }
        let reached = closure(&objects[index], ledger.refs.iter().map(|held| &held.head)).map_err(
            |missing| {
                invalid(format!(
                    "the ledger `{}` reaches {missing}, which the bundle does not carry",
                    ledger.name
                ))
            },
        )?;
        if reached.len() != objects[index].len() {
            return Err(invalid(format!(
                "the bundle carries objects no ref of `{}` reaches",
                ledger.name
            )));
        }
        if ledger.objects != objects[index].len() as u64
            || ledger.statements != statements[index].len() as u64
        {
            return Err(invalid(format!(
                "the bundle's counts of `{}` are not the manifest's",
                ledger.name
            )));
        }
    }
    Ok(Verified {
        manifest_digest: Digest::compute(envelope).to_string(),
        manifest,
        objects,
    })
}

/// Every object `heads` reach through `objects`, or the first digest they reach and it lacks.
fn closure<'a>(
    objects: &BTreeMap<Digest, Vec<u8>>,
    heads: impl Iterator<Item = &'a Digest>,
) -> Result<BTreeSet<Digest>, Digest> {
    let mut reached = BTreeSet::new();
    let mut queue: Vec<Digest> = heads.cloned().collect();
    while let Some(digest) = queue.pop() {
        if !reached.insert(digest.clone()) {
            continue;
        }
        let bytes = objects.get(&digest).ok_or_else(|| digest.clone())?;
        // Decoded once already: an object here is canonical.
        match object::decode(bytes) {
            Ok(Object::Commit(commit)) => {
                queue.push(commit.tree);
                queue.push(commit.manifest);
                queue.extend(commit.predecessors);
            }
            Ok(Object::Tree(tree)) => queue.extend(tree.entries.into_iter().map(|e| e.digest)),
            Ok(Object::Blob(_)) | Err(_) => {}
        }
    }
    Ok(reached)
}

/// The zone's archives directory, created on first use.
fn archives(zones_root: &std::path::Path, zone: &Zone) -> Result<Dir, ApiError> {
    Dir::create_root(&zones_root.join(&zone.id))
        .and_then(|dir| dir.subdir(ARCHIVES, true))
        .map_err(internal)
}

/// Every archive the zone keeps.
pub(crate) fn archived(
    zones_root: &std::path::Path,
    zone: &Zone,
) -> Result<Vec<ArchiveRecord>, ApiError> {
    let dir = archives(zones_root, zone)?;
    let mut held = Vec::new();
    for id in dir.subdirs().map_err(internal)? {
        let Some(bytes) = dir
            .subdir(&id, false)
            .and_then(|archive| archive.read(RECORD))
            .map_err(internal)?
        else {
            // An archive a crash left without its record holds nothing yet.
            continue;
        };
        held.push(
            serde_json::from_slice(&bytes)
                .map_err(|error| internal(format!("the archive {id}'s record: {error}")))?,
        );
    }
    Ok(held)
}

/// Keeps the archive verbatim as foreign evidence: never a ledger, never served.
fn keep(
    zones_root: &std::path::Path,
    zone: &Zone,
    request: &Request<'_>,
    verified: &Verified,
) -> Result<ArchiveRecord, Refusal> {
    let manifest = &verified.manifest;
    let name = match (request.name, manifest.ledgers.as_slice()) {
        (Some(name), _) => name.to_owned(),
        (None, [only]) => only.name.clone(),
        (None, _) => manifest.zone_name.clone(),
    };
    permguard_core::catalog::validate_name(&name).map_err(super::api_error)?;
    if archived(zones_root, zone)?
        .iter()
        .any(|record| record.name == name)
    {
        return Err(conflict(format!(
            "the zone `{}` keeps an archive named `{name}`: name the import otherwise",
            zone.name
        ))
        .into());
    }
    let id = permguard_host::api::replay::mint_id().map_err(|_| internal("no archive id"))?;
    let record = ArchiveRecord {
        id: id.clone(),
        name,
        imported_at: permguard_host::authz::store::now(),
        manifest_digest: verified.manifest_digest.clone(),
        source_host_id: hex(&manifest.host_id),
        source_zone_id: manifest.zone_id.clone(),
        source_zone_name: manifest.zone_name.clone(),
        ledgers: manifest
            .ledgers
            .iter()
            .map(|ledger| ArchivedLedger {
                id: ledger.id.clone(),
                name: ledger.name.clone(),
                refs: ledger.refs.len() as u64,
                objects: ledger.objects,
                statements: ledger.statements,
            })
            .collect(),
    };
    let dir = archives(zones_root, zone)?
        .subdir(&id, true)
        .map_err(internal)?;
    let archive = request.archive.to_vec();
    publish_immutable(&dir, ARCHIVE, &archive, &|read| read == archive, &|held| {
        held == archive
    })
    .map_err(internal)?;
    // The record last: an archive without one is not listed.
    let body = serde_json::to_vec(&record).map_err(internal)?;
    publish_immutable(&dir, RECORD, &body, &|read| read == body, &|held| {
        held == body
    })
    .map_err(internal)?;
    Ok(record)
}

/// Creates a ledger per source ledger, its provenance recorded, and lands its objects.
async fn rehome(
    facade: &CatalogFacade,
    actor: &Actor,
    zones_root: &std::path::Path,
    zone: &Zone,
    request: &Request<'_>,
    verified: &Verified,
) -> Result<Vec<Ledger>, Refusal> {
    let manifest = &verified.manifest;
    if request.name.is_some() && manifest.ledgers.len() != 1 {
        return Err(invalid(
            "a name re-homes a one-ledger archive: the ledgers of a zone keep their names",
        )
        .into());
    }
    let names: Vec<String> = manifest
        .ledgers
        .iter()
        .map(|ledger| {
            request
                .name
                .map_or_else(|| ledger.name.clone(), str::to_owned)
        })
        .collect();
    let request_ids: Vec<String> = (0..names.len())
        .map(|index| format!("{}#{index}", request.request_id))
        .collect();
    let change = |index: usize| super::Change {
        request_id: &request_ids[index],
        request: serde_json::json!({
            "zone": zone.id,
            "name": names[index],
            "imported": verified.manifest_digest,
            "ledger": manifest.ledgers[index].id,
        }),
        name: Some(&names[index]),
    };
    // What this request already created, a retry's to resume rather than to refuse.
    let mut replayed = Vec::new();
    for index in 0..names.len() {
        replayed.push(
            facade
                .replayed(actor, super::LEDGER_CREATE, &change(index))
                .await?,
        );
    }
    // Every other name free before anything is written; what the catalog creates meanwhile, or a
    // crash, can still stop the loop below after some (see the module's note).
    let held = facade
        .catalog
        .list_ledgers(&Selector::Id(zone.id.clone()))
        .map_err(super::api_error)?;
    if let Some(taken) = names
        .iter()
        .zip(&replayed)
        .filter(|(_, replayed)| replayed.is_none())
        .map(|(name, _)| name)
        .find(|name| held.iter().any(|ledger| &ledger.name == *name))
    {
        return Err(conflict(format!(
            "the zone `{}` holds a ledger named `{taken}`: an import never replaces one",
            zone.name
        ))
        .into());
    }
    let mut created: Vec<Ledger> = Vec::new();
    let stopped = |created: &[Ledger]| {
        if !created.is_empty() {
            tracing::warn!(
                event.name = "zone.import_stopped",
                component = "control-plane",
                zone = %zone.id,
                created = %created.iter().map(|ledger| ledger.name.as_str()).collect::<Vec<_>>().join(","),
                "a re-home stopped after creating some ledgers: the same request id resumes it"
            );
        }
    };
    for (index, (source, done)) in manifest.ledgers.iter().zip(replayed).enumerate() {
        let provenance = Provenance {
            manifest_digest: verified.manifest_digest.clone(),
            source_host_id: hex(&manifest.host_id),
            source_zone_id: manifest.zone_id.clone(),
            source_ledger_id: source.id.clone(),
            exported_at: manifest.exported_at,
        };
        let outcome = match done {
            Some(done) => Ok(done),
            None => {
                super::ledgers::create_rehomed(
                    facade,
                    actor,
                    zone,
                    &names[index],
                    &provenance,
                    change(index),
                )
                .await
            }
        };
        let ledger = match outcome {
            Ok(ledger) => ledger,
            Err(refused) => {
                stopped(&created);
                return Err(refused);
            }
        };
        // The objects, write-once: a retry after a crash lands what the first did not.
        let store =
            FileObjectStore::new(zones_root.join(&zone.id).join("ledgers").join(&ledger.id));
        for bytes in verified.objects[index].values() {
            if let Err(error) = store.publish_object(bytes) {
                stopped(&created);
                return Err(internal(error).into());
            }
        }
        created.push(Ledger::public(ledger));
    }
    Ok(created)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use std::sync::Arc;

    use permguard_core::Disclosure;
    use permguard_core::authz::{ActorContext, Credential, Principal};
    use permguard_core::catalog::Catalog as _;
    use permguard_core::domains::protected;
    use permguard_objects::cose::Sign1;
    use permguard_std::catalog::FileCatalog;

    use super::super::exports::{self as exporting, Exports};
    use super::*;

    /// A source with one ledger exported, and a target zone to import it into.
    struct Fixture {
        archive: Vec<u8>,
        ring: crate::handles::TestRing,
        source_ledger: Ledger,
        target: CatalogFacade,
        zone: Zone,
        root: std::path::PathBuf,
    }

    fn actor() -> Actor {
        Actor::Authenticated(ActorContext::new(
            Principal::new("spiffe://acme/operator").expect("a principal"),
            Credential::SanUri,
            None,
        ))
    }

    fn fixture(tag: &str) -> Fixture {
        let source = exporting::tests::fixture(&format!("{tag}-source"), 1 << 20);
        let exported = source
            .exports
            .archive(&source.zone, std::slice::from_ref(&source.ledger))
            .expect("exported");
        let root = std::env::temp_dir().join(format!(
            "permguard-import-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        let catalog = Arc::new(FileCatalog::new(root.join("zones")));
        let zone = catalog.create_zone("target").expect("a zone");
        let ring = crate::handles::ring_for_tests(&root.join("ring"));
        let target = CatalogFacade {
            host: None,
            authorization: Arc::new(permguard_host::composition::Authorization::permissive()),
            mutations: Some(crate::handles::catalog_mutations_for_tests(
                &root.join("host"),
            )),
            catalog,
            recorder: None,
            disclosure: Disclosure::Full,
            audit_refusals: false,
            metrics: permguard_core::metrics::Metrics::none(),
            exports: Some(Arc::new(Exports::new(
                root.join("zones"),
                crate::handles::export_signer_for_tests(ring),
                [9; 16],
                1 << 20,
            ))),
        };
        Fixture {
            archive: exported.archive,
            ring: Arc::clone(&source.ring),
            source_ledger: source.ledger,
            target,
            zone,
            root,
        }
    }

    /// Verifies a manifest under the source's own ring: what the keys bundle and pin do in a
    /// deployment, which `exports::verify` is tested for in the Host.
    fn under(
        ring: &crate::handles::TestRing,
    ) -> impl Fn(&[u8]) -> Result<exports::Verified, String> + Sync + '_ {
        move |envelope: &[u8]| {
            let jwk = ring
                .public_keys()
                .map_err(|error| error.to_string())?
                .into_iter()
                .next()
                .ok_or("no key")?;
            let (suite, public) =
                permguard_host::keys::bundle::public_of(&jwk).ok_or("no public key")?;
            let payload = Sign1::decode(envelope)
                .map_err(|error| error.to_string())?
                .verify(suite, &public, protected::LEDGER_EXPORT)
                .map_err(|error| error.to_string())?
                .to_vec();
            let manifest = Manifest::decode(&payload)?;
            Ok(exports::Verified {
                host_id: manifest.host_id,
                manifest,
            })
        }
    }

    fn request<'a>(
        fixture: &'a Fixture,
        mode: Mode,
        name: Option<&'a str>,
        id: &'a str,
    ) -> Request<'a> {
        Request {
            mode,
            name,
            request_id: id,
            archive: &fixture.archive,
            bundle_manifest: &[],
            bundle_items: &[],
            pin: "",
        }
    }

    fn status(refused: Refusal) -> u16 {
        match refused {
            Refusal::Api(error) => error.http_status(),
            Refusal::Denied(denial) => denial.http_status(),
        }
    }

    /// WP-7.10: an `archive` import keeps the archive verbatim as foreign evidence under a name:
    /// no ledger is created, nothing is served, and a name the zone keeps is refused while
    /// another is a second archive.
    #[tokio::test]
    async fn an_archive_import_keeps_the_archive_and_creates_no_ledger() {
        let fixture = fixture("archive");
        let check = under(&fixture.ring);
        let imported = import_with(
            &fixture.target,
            &actor(),
            &fixture.zone.id,
            &request(&fixture, Mode::Archive, None, "r-1"),
            &check,
        )
        .await
        .expect("imported");
        let record = imported.archive.expect("an archive");
        assert_eq!(record.name, fixture.source_ledger.name);
        assert_eq!(record.ledgers[0].id, fixture.source_ledger.id);
        assert_eq!(record.source_host_id, hex(&[7; 16]));
        assert!(imported.ledgers.is_empty());
        let kept = std::fs::read(
            fixture
                .root
                .join("zones")
                .join(&fixture.zone.id)
                .join(ARCHIVES)
                .join(&record.id)
                .join(ARCHIVE),
        )
        .expect("kept");
        assert_eq!(kept, fixture.archive, "verbatim");
        assert!(
            fixture
                .target
                .catalog
                .list_ledgers(&Selector::Id(fixture.zone.id.clone()))
                .expect("listed")
                .is_empty(),
            "never a ledger of the target"
        );

        let refused = import_with(
            &fixture.target,
            &actor(),
            &fixture.zone.id,
            &request(&fixture, Mode::Archive, None, "r-2"),
            &check,
        )
        .await
        .expect_err("the name is kept");
        assert_eq!(status(refused), 409);
        import_with(
            &fixture.target,
            &actor(),
            &fixture.zone.id,
            &request(&fixture, Mode::Archive, Some("evidence-2"), "r-3"),
            &check,
        )
        .await
        .expect("another name");
        let held = archived(&fixture.root.join("zones"), &fixture.zone).expect("listed");
        assert_eq!(held.len(), 2);
    }

    /// WP-7.10: a `re-home` import creates a new ledger under this Host, its provenance in its
    /// catalog record, its objects landed and no ref, so it serves only once an operator pushes;
    /// a name the zone holds is refused before anything is written.
    #[tokio::test]
    async fn a_rehome_import_creates_a_new_ledger_with_its_provenance_and_no_ref() {
        let fixture = fixture("rehome");
        let check = under(&fixture.ring);
        let imported = import_with(
            &fixture.target,
            &actor(),
            &fixture.zone.id,
            &request(&fixture, Mode::ReHome, None, "r-1"),
            &check,
        )
        .await
        .expect("imported");
        let ledger = &imported.ledgers[0];
        assert_ne!(ledger.id, fixture.source_ledger.id, "a new identifier");
        assert_eq!(ledger.name, fixture.source_ledger.name);
        let provenance = ledger.provenance.as_ref().expect("its provenance");
        assert_eq!(provenance.source_ledger_id, fixture.source_ledger.id);
        assert_eq!(provenance.manifest_digest, imported.manifest_digest);
        assert_eq!(provenance.source_host_id, hex(&[7; 16]));
        assert_eq!(imported.mode, "re-home");
        assert!(provenance.exported_at > 1_700_000_000);
        assert_eq!(provenance.source_zone_id, imported.source_zone_id);
        // A retry of the same request resumes, never refuses: the same ledger, its objects whole.
        let again = import_with(
            &fixture.target,
            &actor(),
            &fixture.zone.id,
            &request(&fixture, Mode::ReHome, None, "r-1"),
            &check,
        )
        .await
        .expect("a retry");
        assert_eq!(again.ledgers[0].id, ledger.id);
        let read = fixture
            .target
            .catalog
            .get_ledger(
                &Selector::Id(fixture.zone.id.clone()),
                &Selector::Id(ledger.id.clone()),
            )
            .expect("in the catalog");
        assert_eq!(read.provenance.as_ref(), Some(provenance));
        let store = FileObjectStore::new(
            fixture
                .root
                .join("zones")
                .join(&fixture.zone.id)
                .join("ledgers")
                .join(&ledger.id),
        );
        assert_eq!(store.list_objects().expect("listed").len(), 4);
        assert!(
            store.list_refs().expect("listed").is_empty(),
            "no ref until a push"
        );

        let refused = import_with(
            &fixture.target,
            &actor(),
            &fixture.zone.id,
            &request(&fixture, Mode::ReHome, None, "r-2"),
            &check,
        )
        .await
        .expect_err("the name is taken");
        assert_eq!(status(refused), 409);
        let again = import_with(
            &fixture.target,
            &actor(),
            &fixture.zone.id,
            &request(&fixture, Mode::ReHome, Some("release-copy"), "r-3"),
            &check,
        )
        .await
        .expect("another name");
        assert_ne!(again.ledgers[0].id, ledger.id);
    }

    /// WP-7.10: an import needs `catalog.write` and `policy.push` on the zone; either alone is
    /// refused before the archive is read.
    #[tokio::test]
    async fn an_import_needs_catalog_write_and_policy_push() {
        use permguard_core::authz::Selector as Granted;
        use permguard_host::authz::PublicGrant;

        let mut fixture = fixture("authz");
        let check = under(&fixture.ring);
        for operation in [operations::CATALOG_WRITE, operations::POLICY_PUSH] {
            fixture.target.authorization =
                Arc::new(permguard_host::composition::Authorization::public_only(&[
                    PublicGrant::new(
                        &[operation],
                        Granted::parse("plane/control/*").expect("a selector"),
                    ),
                ]));
            let refused = import_with(
                &fixture.target,
                &actor(),
                &fixture.zone.id,
                &request(&fixture, Mode::ReHome, None, "r-1"),
                &check,
            )
            .await
            .expect_err("one grant alone");
            assert_eq!(status(refused), 403, "{operation}");
        }
    }

    /// An archive whose manifest is `manifest`'s bytes unsigned, over `bundle`: what the checks
    /// after the signature are tested with.
    fn unsigned(manifest: &Manifest, bundle: &[u8]) -> Vec<u8> {
        cbor::encode(&Value::Map(vec![
            (
                Value::Int(1),
                Value::Bytes(manifest.encode().expect("encodes")),
            ),
            (Value::Int(2), Value::Bytes(bundle.to_vec())),
        ]))
        .expect("encodes")
    }

    fn unsigned_check(envelope: &[u8]) -> Result<exports::Verified, String> {
        let manifest = Manifest::decode(envelope)?;
        Ok(exports::Verified {
            host_id: manifest.host_id,
            manifest,
        })
    }

    /// WP-7.10: everything an archive carries is checked before anything is written: a bundle
    /// another than the manifest's, an object reached and missing, one no ref reaches, a count
    /// the bundle does not hold, a statement on an unknown ref, an object carried twice, a
    /// signature that does not verify.
    #[test]
    fn an_archive_that_does_not_hold_together_is_refused() {
        let fixture = fixture("tampered");
        let Value::Map(pairs) = cbor::decode_canonical(&fixture.archive).expect("cbor") else {
            panic!("a map");
        };
        let (Value::Bytes(envelope), Value::Bytes(bundle)) = (&pairs[0].1, &pairs[1].1) else {
            panic!("bytes");
        };
        let payload = Sign1::decode(envelope)
            .expect("COSE")
            .payload_unverified()
            .to_vec();
        let manifest = Manifest::decode(&payload).expect("a manifest");
        let Value::Array(entries) = cbor::decode_canonical(bundle).expect("cbor") else {
            panic!("an array");
        };
        let rebundled =
            |entries: Vec<Value>| cbor::encode(&Value::Array(entries)).expect("encodes");
        let refused = |manifest: &Manifest, bundle: &[u8]| {
            let archive = unsigned(manifest, bundle);
            let request = Request {
                mode: Mode::Archive,
                name: None,
                request_id: "r",
                archive: &archive,
                bundle_manifest: &[],
                bundle_items: &[],
                pin: "",
            };
            verify(&request, &unsigned_check).expect_err("refused")
        };
        let bound = |bundle: &[u8]| Manifest {
            bundle_digest: exports::bundle_digest(bundle),
            bundle_bytes: bundle.len() as u64,
            ..manifest.clone()
        };
        // The signed archive verifies; the same under another check does not.
        let signed = Request {
            mode: Mode::Archive,
            name: None,
            request_id: "r",
            archive: &fixture.archive,
            bundle_manifest: &[],
            bundle_items: &[],
            pin: "",
        };
        verify(&signed, &under(&fixture.ring)).expect("verifies");
        let other = crate::handles::ring_for_tests(&fixture.root.join("other-ring"));
        assert!(verify(&signed, &under(&other)).is_err(), "another key");
        // A bundle the manifest does not bind.
        refused(&manifest, &rebundled(entries[1..].to_vec()));
        // An object reached and missing: the commit's tree dropped.
        let objects: Vec<&Value> = entries.iter().collect();
        let without_one: Vec<Value> = entries
            .iter()
            .filter(|entry| **entry != *objects[0])
            .cloned()
            .collect();
        let short = rebundled(without_one);
        refused(&bound(&short), &short);
        // An object no ref reaches.
        let mut extra = entries.clone();
        extra.push(Value::Map(vec![
            (Value::Int(1), Value::Int(0)),
            (Value::Int(2), Value::Int(OBJECT)),
            (
                Value::Int(3),
                Value::Bytes(
                    permguard_objects::object::Blob {
                        media_type: "application/vnd.permguard.policy.cedar".to_owned(),
                        data: b"unreached".to_vec(),
                    }
                    .encode()
                    .expect("a blob"),
                ),
            ),
        ]));
        let extra = rebundled(extra);
        refused(&bound(&extra), &extra);
        // A count the bundle does not hold.
        let mut counted = bound(bundle);
        counted.ledgers[0].objects += 1;
        refused(&counted, bundle);
        // A statement on a ref the manifest does not name.
        let mut stray = entries.clone();
        stray.push(Value::Map(vec![
            (Value::Int(1), Value::Int(0)),
            (Value::Int(2), Value::Int(STATEMENT)),
            (Value::Int(3), Value::Bytes(b"a statement".to_vec())),
            (Value::Int(4), Value::Text("stray".to_owned())),
        ]));
        let stray = rebundled(stray);
        refused(&bound(&stray), &stray);
        // An object carried twice.
        let mut twice = entries.clone();
        twice.push(entries[0].clone());
        let twice = rebundled(twice);
        refused(&bound(&twice), &twice);
        // A ledger index the manifest does not have.
        let mut nowhere = entries.clone();
        nowhere.push(Value::Map(vec![
            (Value::Int(1), Value::Int(1)),
            (Value::Int(2), Value::Int(OBJECT)),
            (Value::Int(3), Value::Bytes(Vec::new())),
        ]));
        let nowhere = rebundled(nowhere);
        refused(&bound(&nowhere), &nowhere);
    }

    /// The archive `manifest` names unsigned over `entries`, the counts and digest bound.
    fn crafted(manifest: &Manifest, entries: Vec<Value>) -> (Manifest, Vec<u8>) {
        let bundle = cbor::encode(&Value::Array(entries)).expect("encodes");
        let manifest = Manifest {
            bundle_digest: exports::bundle_digest(&bundle),
            bundle_bytes: bundle.len() as u64,
            ..manifest.clone()
        };
        let archive = unsigned(&manifest, &bundle);
        (manifest, archive)
    }

    /// The signed fixture's manifest and bundle entries.
    fn parts_of(fixture: &Fixture) -> (Manifest, Vec<Value>) {
        let Value::Map(pairs) = cbor::decode_canonical(&fixture.archive).expect("cbor") else {
            panic!("a map");
        };
        let (Value::Bytes(envelope), Value::Bytes(bundle)) = (&pairs[0].1, &pairs[1].1) else {
            panic!("bytes");
        };
        let payload = Sign1::decode(envelope)
            .expect("COSE")
            .payload_unverified()
            .to_vec();
        let Value::Array(entries) = cbor::decode_canonical(bundle).expect("cbor") else {
            panic!("an array");
        };
        (Manifest::decode(&payload).expect("a manifest"), entries)
    }

    fn archive_request<'a>(
        archive: &'a [u8],
        mode: Mode,
        name: Option<&'a str>,
        id: &'a str,
    ) -> Request<'a> {
        Request {
            mode,
            name,
            request_id: id,
            archive,
            bundle_manifest: &[],
            bundle_items: &[],
            pin: "",
        }
    }

    /// WP-7.10, after the review: a two-ledger archive keeps the zone's name as an archive,
    /// re-homes both ledgers under their names, and refuses a name given for one.
    #[tokio::test]
    async fn a_zone_archive_is_kept_under_its_zone_and_rehomed_ledger_by_ledger() {
        let fixture = fixture("zone");
        let (manifest, entries) = parts_of(&fixture);
        let mut second = manifest.ledgers[0].clone();
        second.id = "another-id".to_owned();
        second.name = "rules".to_owned();
        let mut doubled = entries.clone();
        for entry in &entries {
            let Value::Map(mut pairs) = entry.clone() else {
                panic!("a map");
            };
            pairs[0].1 = Value::Int(1);
            doubled.push(Value::Map(pairs));
        }
        let two = Manifest {
            ledgers: vec![manifest.ledgers[0].clone(), second],
            ..manifest.clone()
        };
        let (_, archive) = crafted(&two, doubled);

        let refused = import_with(
            &fixture.target,
            &actor(),
            &fixture.zone.id,
            &archive_request(&archive, Mode::ReHome, Some("one-name"), "r-1"),
            &unsigned_check,
        )
        .await
        .expect_err("a name for two ledgers");
        assert_eq!(status(refused), 400);
        // The second name taken: refused before the first ledger is created.
        let taken = fixture
            .target
            .catalog
            .create_ledger(&Selector::Id(fixture.zone.id.clone()), "rules")
            .expect("a ledger of the second name");
        let refused = import_with(
            &fixture.target,
            &actor(),
            &fixture.zone.id,
            &archive_request(&archive, Mode::ReHome, None, "r-0"),
            &unsigned_check,
        )
        .await
        .expect_err("the second name is taken");
        assert_eq!(status(refused), 409);
        let held = fixture
            .target
            .catalog
            .list_ledgers(&Selector::Id(fixture.zone.id.clone()))
            .expect("listed");
        assert_eq!(held.len(), 1, "nothing created: {held:?}");
        fixture
            .target
            .catalog
            .delete_ledger(
                &Selector::Id(fixture.zone.id.clone()),
                &Selector::Id(taken.id.clone()),
            )
            .expect("deleted");
        let kept = import_with(
            &fixture.target,
            &actor(),
            &fixture.zone.id,
            &archive_request(&archive, Mode::Archive, None, "r-2"),
            &unsigned_check,
        )
        .await
        .expect("kept");
        assert_eq!(kept.mode, "archive");
        assert_eq!(kept.archive.expect("an archive").name, manifest.zone_name);
        let rehomed = import_with(
            &fixture.target,
            &actor(),
            &fixture.zone.id,
            &archive_request(&archive, Mode::ReHome, None, "r-3"),
            &unsigned_check,
        )
        .await
        .expect("re-homed");
        let names: Vec<&str> = rehomed
            .ledgers
            .iter()
            .map(|ledger| ledger.name.as_str())
            .collect();
        assert_eq!(names, vec![manifest.ledgers[0].name.as_str(), "rules"]);
    }

    /// WP-7.10, after the review: the size the manifest binds, the statement count, a ref name
    /// outside the grammar and an archive of no ledger are each refused on their own.
    #[test]
    fn each_count_and_name_an_archive_binds_is_checked() {
        let fixture = fixture("counts");
        let (manifest, entries) = parts_of(&fixture);
        let refused = |manifest: &Manifest, archive: &[u8]| {
            let _ = manifest;
            verify(
                &archive_request(archive, Mode::Archive, None, "r"),
                &unsigned_check,
            )
            .expect_err("refused")
        };
        let (bound, archive) = crafted(&manifest, entries.clone());
        verify(
            &archive_request(&archive, Mode::Archive, None, "r"),
            &unsigned_check,
        )
        .expect("the crafted archive holds together");
        // The size alone.
        let mut sized = bound.clone();
        sized.bundle_bytes += 1;
        let bundle = cbor::encode(&Value::Array(entries.clone())).expect("encodes");
        refused(&sized, &unsigned(&sized, &bundle));
        // The statement count alone.
        let mut stated = bound.clone();
        stated.ledgers[0].statements += 1;
        refused(&stated, &unsigned(&stated, &bundle));
        // A ref name outside the grammar.
        let mut named = bound.clone();
        named.ledgers[0].refs[0].name = "bad name".to_owned();
        let without_statement: Vec<Value> = entries
            .iter()
            .filter(|entry| !matches!(entry, Value::Map(pairs) if pairs.len() == 4))
            .cloned()
            .collect();
        let mut unnamed = named.clone();
        unnamed.ledgers[0].statements = 0;
        let (unnamed, archive) = crafted(&unnamed, without_statement);
        let error = refused(&unnamed, &archive);
        assert!(
            error
                .disclosed_message(Disclosure::Full)
                .contains("bad name"),
            "{error:?}"
        );
        // The same entries in another order: the size the manifest binds, not its digest.
        let mut reordered = entries.clone();
        reordered.swap(0, 1);
        let bundle = cbor::encode(&Value::Array(reordered)).expect("encodes");
        assert_eq!(bundle.len() as u64, bound.bundle_bytes);
        refused(&bound, &unsigned(&bound, &bundle));
        // An object no ref reaches, though counted.
        let mut extra = entries.clone();
        extra.push(Value::Map(vec![
            (Value::Int(1), Value::Int(0)),
            (Value::Int(2), Value::Int(OBJECT)),
            (
                Value::Int(3),
                Value::Bytes(
                    permguard_objects::object::Blob {
                        media_type: "application/vnd.permguard.policy.cedar".to_owned(),
                        data: b"unreached".to_vec(),
                    }
                    .encode()
                    .expect("a blob"),
                ),
            ),
        ]));
        let mut counted = bound.clone();
        counted.ledgers[0].objects += 1;
        let (counted, archive) = crafted(&counted, extra);
        let error = refused(&counted, &archive);
        assert!(
            error.disclosed_message(Disclosure::Full).contains("no ref"),
            "{error:?}"
        );
        // A statement on a ref the manifest does not name, though counted.
        let mut stray = entries.clone();
        stray.push(Value::Map(vec![
            (Value::Int(1), Value::Int(0)),
            (Value::Int(2), Value::Int(STATEMENT)),
            (Value::Int(3), Value::Bytes(b"a statement".to_vec())),
            (Value::Int(4), Value::Text("stray".to_owned())),
        ]));
        let mut stated = bound.clone();
        stated.ledgers[0].statements += 1;
        let (stated, archive) = crafted(&stated, stray);
        let error = refused(&stated, &archive);
        assert!(
            error.disclosed_message(Disclosure::Full).contains("stray"),
            "{error:?}"
        );
        // No ledger at all.
        let empty = Manifest {
            ledgers: Vec::new(),
            ..manifest
        };
        let (empty, archive) = crafted(&empty, Vec::new());
        let error = refused(&empty, &archive);
        assert!(
            error
                .disclosed_message(Disclosure::Full)
                .contains("no ledger"),
            "{error:?}"
        );
    }
}
