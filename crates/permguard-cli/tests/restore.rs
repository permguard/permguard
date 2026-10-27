// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! `permguard restore plan|run` (WP-7.9): a snapshot restored offline in one of three modes, the
//! previous owner fenced by a raised claim, the volume scanned and its keys opened before the
//! plan's receipt is written, the run bound to the volume, the mode and the claim it was planned
//! under.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const KEK: &str = "0123456789abcdef0123456789abcdef";
/// The backups' recovery key (TS-5).
const RECOVERY_KEY: &[u8] = b"the right recovery key";

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "permguard-cli-restore-{name}-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("the scratch directory is created");
    dir
}

/// Runs `claim` until the volume's lock is not reported held, for at most five seconds.
///
/// A child process another test thread spawns holds a copy of every descriptor of this process
/// between its fork and its exec — the volume's `LOCK` among them, close-on-exec or not — so a lock
/// this thread has just released can read as held by another process for that instant. Waited
/// out, and bounded: a lock really held elsewhere is still refused.
fn waiting_out_a_spawn<T>(
    mut claim: impl FnMut() -> Result<T, permguard_host::storage::StorageError>,
) -> Result<T, permguard_host::storage::StorageError> {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        match claim() {
            Err(permguard_host::storage::StorageError::Held(_))
                if std::time::Instant::now() < deadline =>
            {
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            claimed => return claimed,
        }
    }
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn json(output: &Output) -> serde_json::Value {
    assert!(output.status.success(), "{}", stderr(output));
    serde_json::from_slice(&output.stdout).expect("the JSON output parses")
}

/// A provisioned volume under a `file` custody, its rings given their first keys as the server's
/// first start gives them, and the commands run on it.
struct Snapshot {
    dir: PathBuf,
    volume: PathBuf,
    config: PathBuf,
}

impl Snapshot {
    fn new(name: &str, assurance: &str) -> Self {
        let dir = scratch(name);
        let volume = dir.join("volume");
        let secrets = dir.join("secrets");
        std::fs::create_dir_all(&secrets).expect("the secrets directory");
        std::fs::write(secrets.join("host-kek"), KEK).expect("the key-encryption key");
        // From `production` every restore resolves the backups' recovery key (TS-5).
        std::fs::write(secrets.join("recovery"), RECOVERY_KEY).expect("the recovery key");
        let config = dir.join("server.yml");
        std::fs::write(
            &config,
            format!(
                "public:\n  http: 0.0.0.0:5556\n{assurance}operations:\n  secrets:\n    \
                 provider: directory\n    directory: {}\n  keys:\n    custody: file\n    \
                 kek_ref: host-kek\n  backup:\n    recovery_key: recovery\n",
                secrets.display()
            ),
        )
        .expect("the configuration writes");
        let snapshot = Self {
            dir,
            volume,
            config,
        };
        json(&snapshot.run(&["host", "identity", "provision"]));
        snapshot.first_start();
        snapshot
    }

    fn run(&self, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_permguard"))
            .arg("-w")
            .arg(&self.dir)
            .arg("-o")
            .arg("json")
            .args(args)
            .arg("--volume")
            .arg(&self.volume)
            .arg("--server-config")
            .arg(&self.config)
            .env("PERMGUARD_CONFIG", self.dir.join("cli-config.yml"))
            .env("NO_COLOR", "1")
            .output()
            .expect("the binary runs")
    }

    fn plan(&self, mode: &str, out: &Path) -> Output {
        self.run(&[
            "restore",
            "plan",
            "--mode",
            mode,
            "--reason",
            "a drill",
            "--out",
            out.to_str().expect("utf-8"),
        ])
    }

    fn restore(&self, mode: &str, plan: &Path) -> Output {
        self.run(&[
            "restore",
            "run",
            "--mode",
            mode,
            "--confirm-file",
            plan.to_str().expect("utf-8"),
        ])
    }

    /// What the server's first start does to every ring: its first key signs at once.
    fn first_start(&self) {
        use permguard_server::offline;
        let config =
            offline::config(env!("CARGO_PKG_VERSION"), Some(&self.config)).expect("the config");
        let held = self.held();
        let custodian = offline::custodian(&config, &held).expect("the custody");
        let host_id = permguard_host::identity::host_id_of(&held)
            .expect("read")
            .expect("provisioned");
        let time = std::sync::Arc::new(permguard_host::time::TimeGuard::system(
            config.time_max_clock_skew(),
        ));
        for ring in offline::rings(&config, &held, host_id, None, &custodian, time).expect("rings")
        {
            ring.maintain_now().expect("maintained");
        }
    }

    fn held(&self) -> permguard_host::storage::volume::Volume {
        waiting_out_a_spawn(|| {
            permguard_host::storage::volume::Volume::claim(
                &self.volume,
                permguard_core::assurance::AssuranceProfile::Development,
            )
        })
        .expect("the volume")
    }

    /// The `BOOT` the last start recorded.
    fn boot(&self) -> permguard_host::identity::record::Boot {
        permguard_host::identity::record::Boot::decode(
            &std::fs::read(self.volume.join("host/identity/BOOT")).expect("a start recorded"),
        )
        .expect("a BOOT")
    }

    /// The recovery operator's `volume claim`: the previous owner fenced.
    fn claim(&self, generation: u64) {
        waiting_out_a_spawn(|| {
            permguard_host::storage::volume::set_claim(&self.volume, generation)
        })
        .expect("claimed");
    }

    fn marker(&self) -> Option<permguard_host::restore::Marker> {
        permguard_host::restore::marked(&self.held()).expect("reads")
    }

    /// Appends `decisions` decision records and `events` event records to the Data Plane's
    /// streams of one ledger, as the server would, under the volume's own identity and
    /// `host.operations` ring: the receipts of each.
    fn append(
        &self,
        decisions: usize,
        events: usize,
    ) -> (
        Vec<permguard_stream::engine::Receipt>,
        Vec<permguard_stream::engine::Receipt>,
    ) {
        use permguard_host::identity::{self, Identity};
        use permguard_server::offline;
        let config =
            offline::config(env!("CARGO_PKG_VERSION"), Some(&self.config)).expect("the config");
        let held = self.held();
        let custodian = offline::custodian(&config, &held).expect("the custody");
        let host_id = identity::host_id_of(&held)
            .expect("read")
            .expect("provisioned");
        let (_, keys) = identity::directories(&held).expect("the identity directory");
        let stored = identity::stored_public(
            permguard_host::storage::Dir::open(keys.path()).expect("the keys"),
        );
        let custodied = custodian
            .plan(
                permguard_host::keys::ring::HOST_IDENTITY,
                host_id,
                keys,
                stored,
                identity::Suite::Ed25519Sha256V1,
            )
            .expect("the identity's custody");
        let opened = Identity::open(&held, custodied.provider).expect("the identity opens");
        let time = std::sync::Arc::new(permguard_host::time::TimeGuard::system(
            config.time_max_clock_skew(),
        ));
        let operations = offline::rings(&config, &held, host_id, None, &custodian, time.clone())
            .expect("rings")
            .into_iter()
            .find(|ring| ring.id() == permguard_host::keys::ring::HOST_OPERATIONS)
            .expect("the operations ring");
        let engine = permguard_stream::engine::Streams::open(&held, &opened, operations, time)
            .expect("the streams");
        let ledger = permguard_core::authz::Resource::ledger("data", "zone-a", "ledger-a");
        let decided = if decisions == 0 {
            Vec::new()
        } else {
            let producer = engine
                .register_producer(
                    permguard_decisions::stream::descriptor(),
                    permguard_decisions::stream::Codec,
                )
                .expect("the decision stream");
            let record = vector("decision_record", 0);
            (0..decisions)
                .map(|_| producer.append(&ledger, &record).expect("appended"))
                .collect()
        };
        let recorded = if events == 0 {
            Vec::new()
        } else {
            let producer = engine
                .register_producer(
                    permguard_events::stream::descriptor(),
                    permguard_events::stream::Codec,
                )
                .expect("the event stream");
            let record = vector("event_batch", 0);
            (0..events)
                .map(|_| producer.append(&ledger, &record).expect("appended"))
                .collect()
        };
        (decided, recorded)
    }

    fn host_id(&self) -> String {
        permguard_host::identity::record::uuid_text(
            &permguard_host::identity::host_id_of(&self.held())
                .expect("read")
                .expect("provisioned"),
        )
    }
}

impl Drop for Snapshot {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// A record the streams' codecs accept, from the evidence vectors: the `n`th decision record, or
/// the `n`th record of the event batch.
fn vector(name: &str, n: usize) -> serde_json::Value {
    let vectors: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../contracts/vectors/evidence.json"
        ))
        .expect("the vectors"),
    )
    .expect("JSON");
    match name {
        "decision_record" => vectors[name][n]["record"].clone(),
        _ => vectors[name]["records"][n].clone(),
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// WP-7.9: a `dr` restore keeps the Host and is a new incarnation of it. Refused until the claim
/// is raised above the snapshot's; its receipt is its owner's only; the run is refused under
/// another mode or another claim; the run records the marker and the volume's next `BOOT` is a
/// new boot id under the new claim; a second restore under the same claim is refused.
#[test]
fn a_dr_restore_keeps_the_host_under_a_new_boot_id_once_per_fence() {
    let snapshot = Snapshot::new("dr", "");
    let host_id = snapshot.host_id();
    let previous = snapshot.boot();
    let plan = snapshot.dir.join("restore.plan");

    // The previous owner is not fenced: nothing is planned or written.
    let unfenced = snapshot.plan("dr", &plan);
    assert!(!unfenced.status.success());
    assert!(
        stderr(&unfenced).contains("does not exceed"),
        "{}",
        stderr(&unfenced)
    );
    assert!(!plan.exists());

    snapshot.claim(previous.generation + 1);
    let planned = json(&snapshot.plan("dr", &plan));
    assert_eq!(planned["mode"], "dr");
    assert_eq!(planned["host_id"], host_id.as_str());
    assert_eq!(planned["generation"], previous.generation + 1);
    assert_eq!(planned["previous_boot_id"], hex(&previous.boot_id));
    // A fresh volume holds no journal segment and no object: the scan reads nothing, and says so.
    assert_eq!(planned["files_checked"], 0);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = std::fs::metadata(&plan)
            .expect("written")
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600, "the plan is its owner's alone");
    }

    // Another mode than the plan's is refused, the plan unspent.
    let other = snapshot.restore("forensic", &plan);
    assert!(!other.status.success());
    assert!(
        stderr(&other).contains("restores in `dr` mode"),
        "{}",
        stderr(&other)
    );
    assert_eq!(snapshot.marker(), None);

    let restored = json(&snapshot.restore("dr", &plan));
    assert_eq!(restored["mode"], "dr");
    assert_eq!(restored["host_id"], host_id.as_str());
    assert_eq!(restored["previous_boot_id"], hex(&previous.boot_id));
    assert_eq!(restored["plan_id"], planned["plan_id"]);
    let marker = snapshot.marker().expect("the restore is recorded");
    assert_eq!(marker.mode, permguard_host::restore::Mode::Dr);
    assert_eq!(marker.generation, previous.generation + 1);
    assert_eq!(marker.previous_boot_id, previous.boot_id);
    assert_eq!(
        hex(&marker.plan_id),
        planned["plan_id"].as_str().expect("an id")
    );
    // Same Host, new incarnation: the boot id the volume records now is not the snapshot's.
    assert_eq!(snapshot.host_id(), host_id);
    let now = snapshot.boot();
    assert_ne!(now.boot_id, previous.boot_id);
    assert_eq!(now.generation, previous.generation + 1);
    assert!(
        permguard_host::restore::serving_refused(&snapshot.held())
            .expect("reads")
            .is_none(),
        "a dr volume serves"
    );

    // Once per fence: a second restore under the same claim is refused, the spent receipt too.
    let again = snapshot.plan("dr", &snapshot.dir.join("again.plan"));
    assert!(!again.status.success());
    assert!(
        stderr(&again).contains("was restored (dr)"),
        "{}",
        stderr(&again)
    );
    let spent = snapshot.restore("dr", &plan);
    assert!(!spent.status.success());
    assert!(
        stderr(&spent).contains("was restored (dr)"),
        "{}",
        stderr(&spent)
    );
}

/// WP-7.7 (owner decision of 2026-10-26): a `dr` restore rolls every producer run of the
/// snapshot over before its marker: the restored Host appends to successors only, from sequence 1,
/// never to a run a coordinator may hold further.
#[test]
fn a_dr_restore_rolls_the_producer_runs_over() {
    let snapshot = Snapshot::new("dr-streams", "");
    let (before, recorded) = snapshot.append(2, 1);
    let previous = snapshot.boot();
    snapshot.claim(previous.generation + 1);
    let plan = snapshot.dir.join("restore.plan");
    json(&snapshot.plan("dr", &plan));
    let restored = json(&snapshot.restore("dr", &plan));
    assert_eq!(
        restored["streams"]["runs_rolled_over"], 2,
        "the decision run and the event run"
    );
    assert_eq!(restored["streams"]["forked"], serde_json::json!([]));
    let (after, recorded_after) = snapshot.append(1, 1);
    assert_ne!(
        after[0].run_id, before[0].run_id,
        "the snapshot's runs are not appended to"
    );
    assert_ne!(recorded_after[0].run_id, recorded[0].run_id);
    assert_eq!((after[0].seq, recorded_after[0].seq), (1, 1));
}

/// WP-7.7: a producer stream the restore cannot roll over refuses a `dr` restore, nothing written.
#[test]
fn a_dr_restore_refuses_a_producer_stream_it_does_not_know() {
    let snapshot = Snapshot::new("dr-unknown-stream", "");
    let unknown = snapshot
        .volume
        .join("host/streams/data/unknown/1/producer/somewhere");
    std::fs::create_dir_all(&unknown).expect("a producer directory");
    let previous = snapshot.boot();
    snapshot.claim(previous.generation + 1);
    let plan = snapshot.dir.join("restore.plan");
    json(&snapshot.plan("dr", &plan));
    let refused = snapshot.restore("dr", &plan);
    assert!(!refused.status.success());
    assert!(
        stderr(&refused).contains("`data/unknown` version 1"),
        "{}",
        stderr(&refused)
    );
    assert!(snapshot.marker().is_none(), "nothing was recorded");
}

/// WP-7.9: the run requires the claim the plan proved the fence under; raised since, it is
/// refused and the receipt stays unspent.
#[test]
fn a_restore_planned_under_another_claim_is_refused() {
    let snapshot = Snapshot::new("claim", "");
    let previous = snapshot.boot();
    let plan = snapshot.dir.join("restore.plan");
    snapshot.claim(previous.generation + 1);
    json(&snapshot.plan("dr", &plan));
    snapshot.claim(previous.generation + 2);
    let moved = snapshot.restore("dr", &plan);
    assert!(!moved.status.success());
    assert!(stderr(&moved).contains("plan again"), "{}", stderr(&moved));
    assert_eq!(snapshot.marker(), None);
}

/// WP-7.9: a `forensic` restore is never served: the marker refuses the server's start.
#[test]
fn a_forensic_restore_is_never_served() {
    let snapshot = Snapshot::new("forensic", "");
    let host_id = snapshot.host_id();
    let plan = snapshot.dir.join("restore.plan");
    snapshot.claim(snapshot.boot().generation + 1);
    json(&snapshot.plan("forensic", &plan));
    let restored = json(&snapshot.restore("forensic", &plan));
    assert_eq!(restored["mode"], "forensic");
    assert_eq!(restored["host_id"], host_id.as_str());
    assert_eq!(
        snapshot.marker().expect("recorded").mode,
        permguard_host::restore::Mode::Forensic
    );
    assert!(
        permguard_host::restore::serving_refused(&snapshot.held())
            .expect("reads")
            .is_some()
    );
}

/// WP-7.9: a forensic volume is terminal: a later `dr` restore is refused even under a raised
/// claim, and an offline command that writes refuses it; another forensic restore is not refused.
#[test]
fn a_forensic_volume_is_never_made_servable() {
    let snapshot = Snapshot::new("forensic-terminal", "");
    snapshot.claim(snapshot.boot().generation + 1);
    let plan = snapshot.dir.join("restore.plan");
    json(&snapshot.plan("forensic", &plan));
    json(&snapshot.restore("forensic", &plan));
    snapshot.claim(snapshot.boot().generation + 1);
    let dr = snapshot.plan("dr", &snapshot.dir.join("dr.plan"));
    assert!(!dr.status.success());
    assert!(
        stderr(&dr).contains("restored for forensics"),
        "{}",
        stderr(&dr)
    );
    let fingerprint = "ab".repeat(32);
    let written = snapshot.run(&["host", "grants", "bootstrap", "--fingerprint", &fingerprint]);
    assert!(!written.status.success());
    assert!(
        stderr(&written).contains("nothing is written to it"),
        "{}",
        stderr(&written)
    );
    json(&snapshot.plan("forensic", &snapshot.dir.join("again.plan")));
}

/// WP-7.9: a receipt confirms one restore of one volume: another volume's, or another
/// operation's on this volume, is refused and nothing is recorded.
#[test]
fn a_receipt_of_another_volume_or_operation_is_refused() {
    let first = Snapshot::new("receipt-a", "");
    let second = Snapshot::new("receipt-b", "");
    first.claim(first.boot().generation + 1);
    second.claim(second.boot().generation + 1);
    let plan = first.dir.join("restore.plan");
    json(&first.plan("dr", &plan));
    let foreign = second.restore("dr", &plan);
    assert!(!foreign.status.success());
    assert!(
        stderr(&foreign).contains("--confirm-file"),
        "{}",
        stderr(&foreign)
    );
    assert_eq!(second.marker(), None);

    let reset = second.dir.join("reset.plan");
    json(&second.run(&[
        "host",
        "identity",
        "reset",
        "plan",
        "--reason",
        "a drill",
        "--out",
        reset.to_str().expect("utf-8"),
    ]));
    let other = second.restore("dr", &reset);
    assert!(!other.status.success());
    assert!(
        stderr(&other).contains("not a restore's receipt"),
        "{}",
        stderr(&other)
    );
    assert_eq!(second.marker(), None);
}

/// WP-7.9: a `clone` restore is a new Host: the emergency reset gives it a new identity and the
/// old one retires, so nothing the snapshot's Host held is started under it.
#[test]
fn a_clone_restore_is_a_new_host() {
    let snapshot = Snapshot::new("clone", "");
    let host_id = snapshot.host_id();
    let plan = snapshot.dir.join("restore.plan");
    snapshot.claim(snapshot.boot().generation + 1);
    json(&snapshot.plan("clone", &plan));
    let restored = json(&snapshot.restore("clone", &plan));
    assert_eq!(restored["mode"], "clone");
    assert_eq!(restored["reset"]["old_host_id"], host_id.as_str());
    assert_ne!(restored["host_id"], host_id.as_str());
    assert_eq!(restored["host_id"], restored["reset"]["host_id"]);
    assert_eq!(
        snapshot.host_id(),
        restored["host_id"].as_str().expect("an id")
    );
    assert!(
        snapshot
            .volume
            .join(format!("host/identity/retired/{host_id}/INIT"))
            .is_file(),
        "the snapshot's identity retired"
    );
    assert_eq!(
        snapshot.marker().expect("recorded").mode,
        permguard_host::restore::Mode::Clone
    );
}

/// WP-7.9: the scan reads every object tree the server verifies: a damaged object refuses the
/// plan before anything is written.
#[test]
fn a_damaged_volume_is_not_restored() {
    let snapshot = Snapshot::new("damaged", "");
    snapshot.claim(snapshot.boot().generation + 1);
    let objects = snapshot.volume.join("data/zones/z1/l1/objects/ab");
    std::fs::create_dir_all(&objects).expect("the tree");
    std::fs::write(objects.join("c".repeat(62)), b"not an object").expect("written");
    let plan = snapshot.dir.join("restore.plan");
    let refused = snapshot.plan("dr", &plan);
    assert!(!refused.status.success());
    assert!(
        stderr(&refused).contains("damaged file"),
        "{}",
        stderr(&refused)
    );
    assert!(!plan.exists());
}

/// WP-7.9: under dual control a restore needs an approval no offline volume can collect yet:
/// it is refused before anything is written.
#[test]
fn under_dual_control_a_restore_is_refused() {
    let snapshot = Snapshot::new(
        "dual",
        "assurance:\n  added_controls: [operations.dual_control]\n",
    );
    snapshot.claim(snapshot.boot().generation + 1);
    let plan = snapshot.dir.join("restore.plan");
    let refused = snapshot.plan("dr", &plan);
    assert!(!refused.status.success());
    assert!(
        stderr(&refused).contains("dual control"),
        "{}",
        stderr(&refused)
    );
    assert!(!plan.exists());
}

/// WP-7.9: the run scans again: damage found after the plan refuses it before the plan is spent
/// or anything recorded.
#[test]
fn damage_after_the_plan_refuses_the_run() {
    let snapshot = Snapshot::new("damaged-run", "");
    snapshot.claim(snapshot.boot().generation + 1);
    let plan = snapshot.dir.join("restore.plan");
    json(&snapshot.plan("dr", &plan));
    let objects = snapshot.volume.join("data/zones/z1/l1/objects/ab");
    std::fs::create_dir_all(&objects).expect("the tree");
    std::fs::write(objects.join("c".repeat(62)), b"not an object").expect("written");
    let refused = snapshot.restore("dr", &plan);
    assert!(!refused.status.success());
    assert!(
        stderr(&refused).contains("damaged file"),
        "{}",
        stderr(&refused)
    );
    assert_eq!(snapshot.marker(), None);
    // The plan is unspent: repaired, the volume restores under it.
    std::fs::remove_dir_all(snapshot.volume.join("data/zones/z1")).expect("repaired");
    json(&snapshot.restore("dr", &plan));
}

/// WP-7.9: the run opens every ring before its first write: a ring whose private key is gone
/// refuses the run, the plan unspent and nothing recorded.
#[test]
fn a_missing_ring_key_refuses_the_run_before_any_write() {
    let snapshot = Snapshot::new("keys", "");
    snapshot.claim(snapshot.boot().generation + 1);
    let plan = snapshot.dir.join("restore.plan");
    json(&snapshot.plan("clone", &plan));
    let private = snapshot.volume.join("host/keys/host.operations/private");
    let moved = snapshot.dir.join("private");
    std::fs::rename(&private, &moved).expect("the key moved away");
    let refused = snapshot.restore("clone", &plan);
    assert!(!refused.status.success());
    assert!(
        stderr(&refused).contains("the key rings"),
        "{}",
        stderr(&refused)
    );
    assert_eq!(snapshot.marker(), None);
    // Unspent: the key back, the restore runs under the same plan.
    std::fs::rename(&moved, &private).expect("the key back");
    json(&snapshot.restore("clone", &plan));
}

/// Lays out what a snapshot taken inside the barrier holds (TS-5): a backup still `prepared`, its
/// manifest binding `recovery_key_id`.
fn prepared_backup(snapshot: &Snapshot, recovery_key_id: Option<&str>) {
    use permguard_host::operations::backup::{self, SnapshotManifest, State};

    let held = snapshot.held();
    let backups = held
        .host()
        .subdir(backup::DIRECTORY, true)
        .expect("backups");
    let dir = backups.subdir("0190aaaa", true).expect("the backup");
    let manifest = SnapshotManifest {
        operation_id: [1; 16],
        volume_id: held.id(),
        host_id: [3; 16],
        revisions: std::collections::BTreeMap::from([("mutations".to_owned(), 1)]),
        roots: Vec::new(),
        at: 1_800_000_000,
        inventory_digest: [0; 32],
        recovery_key_id: recovery_key_id.map(str::to_owned),
        encryption_profile: Some("aes-256-gcm".to_owned()),
    };
    // Read unverified by the restore: any signature bytes do.
    let envelope = permguard_objects::cose::Sign1::sign_with(
        permguard_objects::crypto::suite::Suite::Ed25519Sha256V1,
        permguard_core::domains::protected::SNAPSHOT_MANIFEST,
        b"kid",
        manifest.encode().expect("encodes"),
        |_| Ok(vec![0; 64]),
    )
    .expect("signs")
    .encode()
    .expect("encodes");
    permguard_host::storage::write::replace_bytes(&dir, backup::MANIFEST, &envelope)
        .expect("the manifest");
    backup::write_state(
        &dir,
        &State {
            state: backup::PREPARED.to_owned(),
            at: 1_800_000_000,
            snapshot_id: None,
        },
    )
    .expect("the state");
}

/// Names `key` as the backups' recovery key in the snapshot's server configuration, or none.
fn recovery_key(snapshot: &Snapshot, key: Option<&str>) {
    let text = std::fs::read_to_string(&snapshot.config).expect("reads");
    // The backup section is the last one, when it is there.
    let mut text = text
        .split_once("  backup:\n")
        .map_or(text.as_str(), |(kept, _)| kept)
        .to_owned();
    if let Some(key) = key {
        text.push_str(&format!("  backup:\n    recovery_key: {key}\n"));
    }
    std::fs::write(&snapshot.config, text).expect("writes");
}

/// TS-5: a restore proceeds only with the recovery key the snapshot's manifest binds: none, or
/// another, is refused before anything is written, the plan never issued; the right one plans and
/// runs.
#[test]
fn a_restore_needs_the_recovery_key_the_snapshot_binds() {
    let snapshot = Snapshot::new("recovery-key", "");
    let secrets = snapshot.dir.join("secrets");
    std::fs::write(secrets.join("other"), b"another recovery key").expect("another key");
    let bound = permguard_host::operations::backup::recovery_key_id(RECOVERY_KEY);
    prepared_backup(&snapshot, Some(&bound));
    snapshot.claim(snapshot.boot().generation + 1);
    let plan = snapshot.dir.join("restore.plan");

    recovery_key(&snapshot, None);
    let refused = snapshot.plan("dr", &plan);
    assert!(!refused.status.success());
    assert!(
        stderr(&refused).contains("recovery_key_missing"),
        "{}",
        stderr(&refused)
    );
    assert!(!plan.exists(), "no plan issued");

    recovery_key(&snapshot, Some("other"));
    let refused = snapshot.plan("dr", &plan);
    assert!(!refused.status.success());
    assert!(
        stderr(&refused).contains("recovery_key_mismatch"),
        "{}",
        stderr(&refused)
    );
    assert!(stderr(&refused).contains(&bound), "{}", stderr(&refused));
    assert!(!plan.exists(), "no plan issued");

    recovery_key(&snapshot, Some("recovery"));
    json(&snapshot.plan("dr", &plan));
    json(&snapshot.restore("dr", &plan));
    assert!(snapshot.marker().is_some(), "restored");
}

/// TS-5: the run checks the key again: a configuration changed after the plan to another key
/// refuses the run, the plan unspent and nothing recorded.
#[test]
fn a_wrong_recovery_key_refuses_the_run_before_any_write() {
    let snapshot = Snapshot::new("recovery-key-run", "");
    let secrets = snapshot.dir.join("secrets");
    std::fs::write(secrets.join("other"), b"another recovery key").expect("another key");
    let bound = permguard_host::operations::backup::recovery_key_id(RECOVERY_KEY);
    prepared_backup(&snapshot, Some(&bound));
    snapshot.claim(snapshot.boot().generation + 1);
    let plan = snapshot.dir.join("restore.plan");
    recovery_key(&snapshot, Some("recovery"));
    json(&snapshot.plan("dr", &plan));
    recovery_key(&snapshot, Some("other"));
    let refused = snapshot.restore("dr", &plan);
    assert!(!refused.status.success());
    assert!(
        stderr(&refused).contains("recovery_key_mismatch"),
        "{}",
        stderr(&refused)
    );
    assert_eq!(snapshot.marker(), None, "nothing recorded");
}
