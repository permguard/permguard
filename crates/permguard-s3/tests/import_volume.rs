// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The import of one volume into PostgreSQL and S3 (iteration 03, WP-28.1): every store written
//! on files, imported by `permguard_s3::import::volume`, and read back through the stores the
//! backend composes a process with, under the names it keeps them under.
//!
//! The tests need both servers, as `control_plane.rs` says, and are skipped without them.

#![allow(clippy::expect_used)]

use std::collections::BTreeMap;
use std::sync::Arc;

use permguard_authority_plane::tokens::files::FileTokens;
use permguard_authority_plane::tokens::{TokenDraft, TokenStore as _};
use permguard_control_plane::decisions::cursorkey::CursorRoots as _;
use permguard_control_plane::decisions::cursorkey::files::FileCursorRoots;
use permguard_control_plane::store::{FileLedgers, LedgerStore as _};
use permguard_core::Config;
use permguard_core::assurance::AssuranceProfile;
use permguard_core::authz::{Selector, TokenScope};
use permguard_core::catalog::{Catalog as _, Selector as Named};
use permguard_host::audit::record::{AuditRecord, genesis};
use permguard_host::audit::store::{FileTrails, Trails as _};
use permguard_host::audit::{Class, HOST, trail};
use permguard_host::identity::files::FileIdentity;
use permguard_host::identity::store::IdentityStore as _;
use permguard_host::keys::ring::HOST_OPERATIONS;
use permguard_host::keys::ring::files::FileRing;
use permguard_host::keys::ring::store::RingStore as _;
use permguard_host::keys::slots::files::FileSlots;
use permguard_host::keys::slots::{Kind, SlotStore};
use permguard_host::membership::files::FileMembers;
use permguard_host::membership::store::MemberStore as _;
use permguard_host::storage::Dir;
use permguard_host::storage::volume::Volume;
use permguard_host::time::ClockMark as _;
use permguard_objects::cbor::{self, Value};
use permguard_objects::digest::Digest;
use permguard_objects::object::Blob;
use permguard_postgres::testing::{Cases, server};
use permguard_s3::backend::Connected;
use permguard_s3::testing::scratch;
use permguard_stream::engine::consumer::export;
use permguard_stream::engine::consumer::store::{FileRuns, Runs as _};

/// 2026-11-20T12:00:00Z.
const NOW: u64 = 1_795_176_000;
/// What a slot holds of a sealed key: a CBOR map, never a DER `SEQUENCE`.
const SEALED: &[u8] = &[0xa8, 0x01, 0x02, 0x03];

/// A volume of its own below the temporary directory, claimed, and its root.
fn claimed(name: &str) -> (std::path::PathBuf, Volume) {
    let root = std::env::temp_dir().join(format!(
        "permguard-import-volume-{name}-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&root);
    let volume = Volume::claim(&root, AssuranceProfile::Development).expect("claimed");
    (root, volume)
}

/// The server's configuration on the backend, its working directory the volume.
fn config(root: &std::path::Path) -> Config {
    Config::from_layers(
        permguard_core::config::BuildSettings::new("0.0.0-test", "2022", "test"),
        Vec::<&str>::new(),
        permguard_core::config::Layers {
            command_line: vec![(
                permguard_core::config::SETTING_WORKING_DIR.to_owned(),
                root.display().to_string(),
            )],
            ..Default::default()
        },
    )
    .expect("the configuration builds")
}

fn item(text: &str, n: i64) -> Vec<u8> {
    cbor::encode(&Value::Array(vec![
        Value::Int(n),
        Value::Text(text.to_owned()),
    ]))
    .expect("an item encodes")
}

fn record(at: u64) -> AuditRecord {
    AuditRecord {
        trail: format!("security:{HOST}"),
        seq: 0,
        operation_id: None,
        phase: None,
        host_id: [1; 16],
        boot_id: [2; 16],
        component: "host".to_owned(),
        action: "server.start".to_owned(),
        principal: "system:test".to_owned(),
        resource: HOST.to_owned(),
        target: Some("the import".to_owned()),
        outcome: "ok".to_owned(),
        facts: BTreeMap::new(),
        build: "9.9.9".to_owned(),
        config_revision: Digest::compute(b"settings"),
        at,
        monotonic_offset: 0,
        previous: genesis(),
    }
}

/// The identity's records and a sealed key in its slot.
fn identity(volume: &Volume) -> FileIdentity {
    let identity = FileIdentity::open(volume).expect("opens");
    identity.publish_init(b"init").expect("kept");
    identity.replace_document(b"document").expect("kept");
    identity
        .append_succession(&item("succession", 1))
        .expect("kept");
    identity.publish_public(1, b"key 1").expect("kept");
    identity.record_start(b"the start").expect("kept");
    let (_, keys) = permguard_host::identity::files::directories(volume).expect("a directory");
    FileSlots::new(keys)
        .fill(Kind::Key, "1", SEALED)
        .expect("kept");
    identity
}

/// Every store a Control Plane or an Authority Plane keeps, written on files, imported, and read
/// back through the stores the backend composes a process with.
#[test]
fn a_volume_is_imported_whole_and_read_as_a_process_reads_it() {
    let test = "a_volume_is_imported_whole_and_read_as_a_process_reads_it";
    let (Some(server), Some(bucket)) = (server(test), scratch(test)) else {
        return;
    };
    let (root, volume) = claimed("whole");
    let config = config(&root);

    let identity = identity(&volume);
    let ring_dir =
        permguard_host::keys::ring::files::directory(&volume, HOST_OPERATIONS).expect("a ring");
    let ring =
        FileRing::open(Dir::open(ring_dir.path()).expect("opens"), HOST_OPERATIONS).expect("opens");
    ring.append(1, &item("entry", 1)).expect("kept");
    ring.replace_view(b"view").expect("kept");
    ring.publish_public("thumbprint", b"jwk").expect("kept");
    let private = FileSlots::new(
        ring_dir
            .subdir(permguard_host::keys::ring::files::PRIVATE, true)
            .expect("a directory"),
    );
    private.fill(Kind::Key, "thumbprint", SEALED).expect("kept");
    private
        .fill(Kind::Reference, "named", b"a KMS key's name")
        .expect("kept");

    let members = FileMembers::open(&volume).expect("opens");
    members.append(1, &item("entry", 1)).expect("kept");
    members.replace_summary(b"summary").expect("kept");
    let mark = i64::try_from(NOW).expect("a mark");
    permguard_host::time::files::FileClockMark::open(&volume)
        .expect("opens")
        .raise(mark)
        .expect("raised");
    {
        let (trails, _) = FileTrails::open(&volume, "2026-11-20.cborseq").expect("opens");
        for n in 0..3 {
            trails
                .hold(Class::Security, HOST, None, &mut |trail| {
                    trail.append(record(NOW + n)).expect("appended");
                    true
                })
                .expect("held");
        }
    }

    let catalog = permguard_std::catalog::FileCatalog::new(config.zones_directory());
    let zone = catalog.create_zone("payments").expect("created");
    let ledger = catalog
        .create_ledger(&Named::Id(zone.id.clone()), "orders")
        .expect("created");
    let files = FileLedgers::new(config.zones_directory()).file(&zone.id, &ledger.id);
    let digest = files
        .put_object(
            &Blob {
                media_type: permguard_core::domains::media::POLICY_CEDAR.to_owned(),
                data: b"permit(principal, action, resource);".to_vec(),
            }
            .encode()
            .expect("a blob"),
        )
        .expect("landed")
        .0;
    let refs =
        permguard_control_plane::store::testing::offline_ref_mutations(&std::env::temp_dir().join(
            format!("permguard-import-volume-refs-{}", std::process::id()),
        ))
        .expect("the engine opens");
    permguard_control_plane::store::testing::operation(&refs, &mut |applying| {
        files
            .update_ref(applying, "main", None, &digest)
            .expect("created");
    });
    let decisions =
        FileCursorRoots::new(config.working_dir().join(config.decision_store_directory()))
            .roots()
            .expect("minted");

    let authority = root
        .join(permguard_host::composition::PLANES)
        .join(permguard_authority_plane::PLANE);
    let (tokens, _) = FileTokens::open(
        &Dir::create_root(&authority).expect("a directory"),
        permguard_host::storage::journal::Options::default(),
    )
    .expect("opens");
    let issued = tokens
        .issue(
            TokenDraft {
                account: "billing".to_owned(),
                access_key: "pgak_AAAAAAAAAAAAAAAAAAAA".to_owned(),
                scopes: vec![TokenScope {
                    operations: std::iter::once("decision.evaluate".to_owned()).collect(),
                    selector: Selector::parse("plane/data/*").expect("a selector"),
                }],
                expires_at: NOW + 3_600,
            },
            NOW,
        )
        .expect("issued");

    let consumer = volume
        .host()
        .subdir(permguard_stream::engine::STREAMS, true)
        .and_then(|streams| streams.subdir("control-plane", true))
        .and_then(|plane| plane.subdir("decisions", true))
        .and_then(|stream| stream.subdir("1", true))
        .and_then(|version| version.subdir("consumer", true))
        .expect("a directory");
    let runs = FileRuns::new(consumer, volume.generation(), 64 * 1024);
    let mut held = runs
        .open(&"a1".repeat(32), &"b2".repeat(16), &"c3".repeat(16), true)
        .expect("opened")
        .expect("created");
    held.append(1, &[7; 40]).expect("appended");
    drop(held);
    let mut kept_runs = export(&runs).expect("exported");

    let cases = Cases::new(server);
    let connected = Connected {
        database: cases.next(),
        bucket,
    };
    let imported = permguard_s3::import::volume(
        &config,
        &volume,
        &connected,
        permguard_postgres::testing::sealer(),
    )
    .expect("imported");
    assert_eq!(imported.deployment, volume.id());
    let carried: BTreeMap<_, _> = imported.stores.iter().copied().collect();
    for (store, records) in [
        ("identity", 1),
        ("identity key slots", 1),
        ("key rings", 1),
        ("key ring slots", 2),
        ("memberships", 2),
        ("clock mark", 1),
        ("audit trails", 1),
        ("zones", 1),
        ("ledgers", 1),
        ("ledger objects", 1),
        ("cursor roots", 1),
        ("tokens", 1),
        ("stream consumers", 1),
    ] {
        assert_eq!(carried.get(store), Some(&records), "{store}");
    }

    // A process on the backend reads what the volume held, under the volume's id.
    let shared = permguard_s3::backend::shared(&connected).expect("composed");
    assert_eq!(shared.home, volume.id());
    assert_eq!(
        shared.identity.init().expect("read"),
        identity.init().expect("read")
    );
    assert!(shared.identity.started().expect("read"));
    assert_eq!(
        shared.identity_slots.read(Kind::Key, "1").expect("read"),
        Some(SEALED.to_vec())
    );
    let stores = shared.rings.stores(HOST_OPERATIONS, None).expect("opens");
    assert_eq!(
        stores.ring.entries().expect("read"),
        ring.entries().expect("read")
    );
    assert_eq!(
        stores.slots.read(Kind::Key, "thumbprint").expect("read"),
        Some(SEALED.to_vec())
    );
    assert_eq!(
        stores.slots.read(Kind::Reference, "named").expect("read"),
        Some(b"a KMS key's name".to_vec())
    );
    assert_eq!(
        shared.members.entries().expect("read"),
        members.entries().expect("read")
    );
    assert_eq!(shared.clock_mark.read().expect("read"), Some(mark));
    let trail = shared
        .trails
        .view(Class::Security, HOST)
        .expect("answered")
        .expect("held");
    assert_eq!(
        trail::state_of(trail.as_ref()).expect("a state").next_seq,
        3
    );
    assert_eq!(
        shared.catalog.list_zones().expect("listed"),
        catalog.list_zones().expect("listed")
    );
    let zones = shared
        .handle::<permguard_control_plane::plane::ZoneStores>()
        .expect("the zones' stores");
    let served = zones.ledgers.ledger(&zone.id, &ledger.id);
    assert_eq!(
        served.read_ref("main").expect("read"),
        files.read_ref("main").expect("read")
    );
    assert_eq!(
        served.get_object(&digest).expect("read"),
        files.get_object(&digest).expect("read")
    );
    let evidence = shared
        .handle::<permguard_control_plane::plane::SharedEvidence>()
        .expect("the evidence");
    let roots = (evidence.cursor_roots)(
        permguard_postgres::testing::sealer(),
        permguard_control_plane::plane::DECISIONS_API,
    )
    .roots()
    .expect("read");
    assert_eq!(roots.issuing, decisions.issuing);
    let authority = shared
        .handle::<permguard_authority_plane::plane::AuthorityStores>()
        .expect("the Authority Plane's stores");
    assert_eq!(
        authority.tokens.token(&issued.jti).expect("read"),
        tokens.token(&issued.jti).expect("read")
    );
    let mut read_runs = export(&permguard_s3::streams::PostgresRuns::new(
        connected.database.clone(),
        connected.bucket.clone(),
        "control-plane/decisions/1",
    ))
    .expect("read back");
    // A frame's claim is the writer's on files; the database keeps none.
    for runs in [&mut read_runs, &mut kept_runs] {
        for run in &mut runs.runs {
            for frame in &mut run.frames {
                frame.claim = 0;
            }
        }
    }
    assert_eq!(read_runs, kept_runs);

    // What the offline verification reads (X101): the trails laid out as on files, one chain each,
    // and the keys of the ring that signs their checkpoints, read without minting anything.
    let (trails, operations) = permguard_s3::backend::audit(&connected);
    let copy = Dir::create_root(&root.join("copy")).expect("a directory");
    assert_eq!(
        permguard_host::audit::store::export(trails.as_ref(), &copy).expect("copied"),
        1
    );
    let copied = trail::directory(&copy, Class::Security, HOST, false).expect("copied");
    assert!(
        copied.read(trail::META).expect("read").is_some(),
        "the trail's META"
    );
    assert!(
        copied
            .names()
            .expect("listed")
            .iter()
            .any(|name| name.ends_with(".cborseq")),
        "the trail's day"
    );
    assert_eq!(
        operations.entries().expect("read"),
        ring.entries().expect("read")
    );
    // A cursor root rotates once; with none issuing there is nothing to move (X110).
    assert!(
        permguard_s3::backend::rotate_cursor_root(
            &connected,
            permguard_control_plane::plane::DECISIONS_API
        )
        .expect("rotated")
    );
    assert!(
        !permguard_s3::backend::rotate_cursor_root(
            &connected,
            permguard_control_plane::plane::DECISIONS_API
        )
        .expect("answered")
    );
    assert!(permguard_s3::backend::rotate_cursor_root(&connected, "ledgers").is_err());
    let _ = std::fs::remove_dir_all(root);
}

/// A key in the clear refuses the import; the database it began on is refused at start, and an
/// import over it does not begin.
#[test]
fn an_import_that_did_not_complete_is_never_served() {
    let test = "an_import_that_did_not_complete_is_never_served";
    let (Some(server), Some(bucket)) = (server(test), scratch(test)) else {
        return;
    };
    let (root, volume) = claimed("refused");
    let config = config(&root);
    identity(&volume);
    let ring_dir =
        permguard_host::keys::ring::files::directory(&volume, HOST_OPERATIONS).expect("a ring");
    FileRing::open(Dir::open(ring_dir.path()).expect("opens"), HOST_OPERATIONS)
        .expect("opens")
        .append(1, &item("entry", 1))
        .expect("kept");
    // A PKCS#8 document starts with a DER `SEQUENCE`.
    FileSlots::new(
        ring_dir
            .subdir(permguard_host::keys::ring::files::PRIVATE, true)
            .expect("a directory"),
    )
    .fill(Kind::Key, "plaintext", &[0x30, 0x2e, 0x02, 0x01])
    .expect("kept");

    let cases = Cases::new(server);
    let connected = Connected {
        database: cases.next(),
        bucket,
    };
    let sealer = || -> Arc<_> { permguard_postgres::testing::sealer() };
    let refused = permguard_s3::import::volume(&config, &volume, &connected, sealer())
        .expect_err("a key in the clear");
    assert!(
        format!("{refused:#}").contains("a key in the clear"),
        "{refused:#}"
    );
    let unserved = permguard_s3::backend::shared(&connected).expect_err("an import under way");
    assert!(
        format!("{unserved:#}").contains("did not complete"),
        "{unserved:#}"
    );
    let again = permguard_s3::import::volume(&config, &volume, &connected, sealer())
        .expect_err("a deployment kept");
    assert!(
        format!("{again:#}").contains("keeps a deployment already"),
        "{again:#}"
    );
    let _ = std::fs::remove_dir_all(root);
}
