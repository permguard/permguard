// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! WP-7.7: a volume the plan's baseline commit wrote recovers through every migration.
//!
//! `tests/fixtures/legacy/baseline-8390f612/volume` is the whole working directory an all-in-one of
//! commit `8390f612` left behind under its experimental configuration, captured once by
//! `scripts/capture-baseline-volume.sh`: `examples/basics` and `examples/dogwood-session-access`
//! applied, decisions recorded and shipped, a temporal trace submitted, the key rings, the audit
//! chain and the secrets it generated. `capture.json` holds what the baseline answered.
//!
//! The upgrade an operator runs on it, with today's binary:
//!
//! | Step                                | What it proves                                                                                                                           |
//! | ----------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------- |
//! | start with the baseline's versions  | refused, naming the two key versions to raise (WP-3.3)                                                                                   |
//! | raise them and start                | the server migrates the audit chain, the decision spool and the rings itself, and answers as the baseline did                            |
//! | `migrate events`, offline           | refused while the Control Plane's store sits inside the history; once it is moved out, the shipped history is archived, past the horizon |
//! | `migrate finalize`, every subsystem | each old generation removed; the rollback horizon ends there                                                                             |
//! | `volume verify` and `audit verify`  | nothing on the volume is damaged; the legacy chain and its seal verify                                                                   |
//! | start again                         | the same answers                                                                                                                         |

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::io::{Read as _, Write as _};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output};
use std::time::{Duration, Instant};

use serde_json::Value;

/// The subsystems the upgrade migrates, every one the baseline's volume holds.
const SUBSYSTEMS: [&str; 6] = [
    "audit-legacy",
    "decisions-legacy",
    "events-legacy",
    "keys-control-attest",
    "keys-data-attest",
    "keys-host-operations",
];

/// The event journal's retention: the least this build admits, what its temporal runtimes look
/// back (a day) with the lateness and the skew below.
const RETENTION_SECONDS: u64 = 86_400 + 5 * 60 + 30;
/// How far behind now the legacy history's archive reads it as drained: the retention, the
/// lateness and the skew again (`permguard_events::archive::horizon`).
const ARCHIVE_HORIZON: Duration = Duration::from_secs(RETENTION_SECONDS + 5 * 60 + 30);

fn fixture() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/legacy/baseline-8390f612")
}

fn examples() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples")
}

/// The binary, without the `PERMGUARD_*` variables of the shell that runs the tests.
fn binary() -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_permguard-all-in-one"));
    for (name, _) in std::env::vars_os() {
        if name.to_string_lossy().starts_with("PERMGUARD_") {
            command.env_remove(name);
        }
    }
    command
}

fn copy_tree(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).expect("a directory");
    for entry in std::fs::read_dir(from).expect("readable") {
        let entry = entry.expect("an entry");
        let target = to.join(entry.file_name());
        if entry.file_type().expect("a type").is_dir() {
            copy_tree(&entry.path(), &target);
        } else {
            std::fs::copy(entry.path(), &target).expect("copied");
        }
    }
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .expect("a port")
        .local_addr()
        .expect("an address")
        .port()
}

/// A copy of the baseline volume and a configuration of today's schema for it.
struct Upgrade {
    dir: PathBuf,
    volume: PathBuf,
    config: PathBuf,
    host: u16,
    control: u16,
    data: u16,
}

impl Upgrade {
    fn new(tag: &str) -> Self {
        let dir =
            std::env::temp_dir().join(format!("permguard-baseline-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let volume = dir.join("volume");
        copy_tree(&fixture().join("volume"), &volume);
        let upgrade = Self {
            config: dir.join("config.yml"),
            volume,
            dir,
            host: free_port(),
            control: free_port(),
            data: free_port(),
        };
        upgrade.configure("v2", "v2");
        upgrade
    }

    /// Today's configuration of the baseline's experimental deployment, with the two key versions
    /// an upgrade from it raises.
    fn configure(&self, pseudonym: &str, zone_keys: &str) {
        let (host, control, data) = (self.host, self.control, self.data);
        std::fs::write(
            &self.config,
            format!(
                "working_dir: {volume}
development_mode: true
autogenerate: true
assurance: {{ profile: development }}
log: {{ level: info, format: json }}
experimental: {{ dogwood: {{ enabled: \"true\" }} }}
host:
  addr: 127.0.0.1:{host}
  authz:
    public:
      - {{ operations: [catalog.read, catalog.write, policy.push], selector: \"plane/control/*\" }}
      - {{ operations: [decision.evaluate, event.submit], selector: \"plane/data/*\" }}
runtime: {{ planes: [control, data] }}
controlPlane:
  public:
    http: {{ enabled: true, addr: 127.0.0.1:{control} }}
    grpc: {{ enabled: true, addr: 127.0.0.1:{control} }}
  decisions: {{ enabled: \"true\", directory: data/decisions/store, retention: 7d }}
  events: {{ enabled: \"true\", directory: data/events/store, retention: 90d }}
dataPlane:
  public:
    http: {{ enabled: true, addr: 127.0.0.1:{data} }}
    grpc: {{ enabled: true, addr: 127.0.0.1:{data} }}
  mirrors:
    enabled: \"true\"
    interval: 1s
  decisions:
    log:
      enabled: \"true\"
      server: {{ url: \"http://127.0.0.1:{control}\" }}
      spool: {{ directory: data/decisions/spool, bytes: 64M, age: 24h }}
      batch: {{ bytes: 256k, interval: 1s }}
      mode: required
      sample: {{ permits: \"1.0\" }}
  events:
    enabled: \"true\"
    directory: data/events
    retention: {{ minimum: {RETENTION_SECONDS}s, allowed_lateness: 5m, clock_skew: 30s }}
    destination: {{ url: \"http://127.0.0.1:{control}\" }}
    pull: {{ mode: local }}
operations:
  keys: {{ enabled: true, publish_ahead: 5m, rotate_every: 1h, retain: 1d }}
  secrets: {{ provider: directory, coordinator_root_ref: zone-root, zone_key_version: \"{zone_keys}\" }}
  audit:
    retention: 7d
    pseudonym: {{ enabled: true, key_ref: audit-pseudonym, key_version: \"{pseudonym}\" }}
",
                volume = self.volume.display(),
            ),
        )
        .expect("the configuration writes");
    }

    /// The operator's step the archive asks for: the baseline kept the Control Plane's event store
    /// inside the legacy event history, which `migrate finalize` removes whole, so the store moves
    /// out of it, and the configuration with it.
    fn move_the_event_store_out(&self) {
        std::fs::rename(
            self.volume.join("data/events/store"),
            self.volume.join("data/events-store"),
        )
        .expect("the event store moves");
        let config = std::fs::read_to_string(&self.config).expect("the configuration");
        assert!(config.contains("directory: data/events/store,"));
        std::fs::write(
            &self.config,
            config.replace(
                "directory: data/events/store,",
                "directory: data/events-store,",
            ),
        )
        .expect("the configuration writes");
    }

    /// Starts the server: `Ok` once it is ready, `Err` with what it said when it exits first.
    fn start(&self) -> Result<Server, String> {
        let log = self.dir.join("server.log");
        let out = std::fs::File::create(&log).expect("a log");
        let mut child = binary()
            .arg(&self.config)
            .stdout(out.try_clone().expect("a handle"))
            .stderr(out)
            .spawn()
            .expect("the server starts");
        let deadline = Instant::now() + Duration::from_secs(90);
        while Instant::now() < deadline {
            if let Ok(Some(_)) = child.try_wait() {
                return Err(std::fs::read_to_string(&log).unwrap_or_default());
            }
            if get(self.host, "/readyz").0 == 200 {
                return Ok(Server { child });
            }
            std::thread::sleep(Duration::from_millis(250));
        }
        let _ = child.kill();
        let _ = child.wait();
        panic!(
            "the server was not ready in time:\n{}",
            std::fs::read_to_string(&log).unwrap_or_default()
        );
    }

    /// Asks the Data Plane about one of `examples/basics`' requests, once the ledger is served.
    fn decide(&self, request: &str) -> bool {
        let path = examples().join("basics/requests").join(request);
        let mut payload: Value =
            serde_json::from_str(&std::fs::read_to_string(&path).expect("a request"))
                .expect("JSON");
        payload["zone"] = "acme".into();
        payload["ledger"] = "main-ledger".into();
        let deadline = Instant::now() + Duration::from_secs(60);
        loop {
            let (status, body) = post(
                self.data,
                permguard_languages::request::EVALUATION_PATH,
                &payload,
            );
            if status == 200 {
                let answer: Value = serde_json::from_str(&body).expect("an answer");
                return answer["decision"].as_bool().expect("a decision");
            }
            assert!(
                Instant::now() < deadline,
                "{request}: the ledger was never served: {status} {body}"
            );
            std::thread::sleep(Duration::from_millis(250));
        }
    }

    /// Runs one of the server binary's offline commands.
    fn offline(&self, args: &[&str]) -> Output {
        binary().args(args).output().expect("the command runs")
    }

    fn volume(&self) -> &str {
        self.volume.to_str().expect("UTF-8")
    }
}

impl Drop for Upgrade {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// A running server, stopped as an orchestrator stops it: `SIGTERM`, then the wait.
struct Server {
    child: Child,
}

impl Server {
    fn stop(mut self) {
        let _ = Command::new("kill")
            .args(["-TERM", &self.child.id().to_string()])
            .status();
        let deadline = Instant::now() + Duration::from_secs(30);
        while Instant::now() < deadline {
            if let Ok(Some(_)) = self.child.try_wait() {
                return;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        if let Ok(None) = self.child.try_wait() {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

/// One plain HTTP exchange on loopback: the status and the body.
fn exchange(port: u16, request: &str) -> (u16, String) {
    let Ok(mut stream) = std::net::TcpStream::connect(("127.0.0.1", port)) else {
        return (0, String::new());
    };
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .expect("a timeout");
    if stream.write_all(request.as_bytes()).is_err() {
        return (0, String::new());
    }
    let mut answer = String::new();
    let _ = stream.read_to_string(&mut answer);
    let status = answer
        .split_whitespace()
        .nth(1)
        .and_then(|status| status.parse().ok())
        .unwrap_or(0);
    let body = answer
        .split_once("\r\n\r\n")
        .map(|(_, body)| body.to_owned())
        .unwrap_or_default();
    (status, body)
}

fn get(port: u16, path: &str) -> (u16, String) {
    exchange(
        port,
        &format!("GET {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n"),
    )
}

fn post(port: u16, path: &str, payload: &Value) -> (u16, String) {
    let body = payload.to_string();
    exchange(
        port,
        &format!(
            "POST {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        ),
    )
}

fn text(output: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

/// What the baseline answered, as the capture recorded it.
fn captured() -> Value {
    serde_json::from_str(
        &std::fs::read_to_string(fixture().join("capture.json")).expect("capture.json"),
    )
    .expect("JSON")
}

/// The answers of `examples/basics` the upgraded server gives, against the baseline's.
fn answers_as_the_baseline(upgrade: &Upgrade) {
    let decided = &captured()["decided"];
    for request in ["permit", "deny", "gateway-permit"] {
        assert_eq!(
            Value::Bool(upgrade.decide(&format!("{request}.json"))),
            decided[request],
            "{request}: answered otherwise than the baseline"
        );
    }
}

#[test]
fn test_the_capture_is_the_baselines() {
    let capture = captured();
    assert_eq!(
        capture["commit"],
        "8390f61244c304ea9b60d3781700cf76838531be"
    );
    // What the example's own tests claim, as the baseline answered it.
    assert_eq!(capture["decided"]["permit"], true);
    assert_eq!(capture["decided"]["deny"], false);
    assert_eq!(capture["decided"]["gateway-permit"], true);
    assert_eq!(capture["temporal"]["read-before-login"], false);
    assert_eq!(capture["temporal"]["read-inside-window"], true);
    assert!(
        capture["captured_at"].as_u64().is_some(),
        "the recovery test reads the archive's horizon from the capture's time"
    );
    // The stores the migrations read, as the baseline laid them out.
    let volume = fixture().join("volume");
    for store in [
        "operations/audit",
        "operations/keys/operations/ring.json",
        "operations/keys/control/ring.json",
        "operations/keys/data/ring.json",
        "data/decisions/spool",
        "data/events",
    ] {
        assert!(
            volume.join(store).exists(),
            "the baseline volume holds {store}"
        );
    }
}

/// Until the operator raises them, the key versions the baseline wrote under refuse the start, and
/// the refusal names the version to raise: nothing is written under a version that now means two
/// keys.
#[test]
fn test_the_baseline_volume_refuses_to_start_until_its_key_versions_are_raised() {
    let upgrade = Upgrade::new("versions");
    upgrade.configure("v1", "v2");
    let refused = upgrade
        .start()
        .err()
        .expect("the baseline's pseudonym version is refused");
    assert!(refused.contains("audit.pseudonym.key_version"), "{refused}");

    let upgrade = Upgrade::new("zone-keys");
    upgrade.configure("v2", "v1");
    let refused = upgrade
        .start()
        .err()
        .expect("the baseline's zone key version is refused");
    assert!(refused.contains("zone_key_version"), "{refused}");
}

#[test]
fn test_the_baseline_volume_recovers_through_every_migration() {
    let upgrade = Upgrade::new("recovers");

    // The baseline mirrored its own Control Plane over a configured URL: its mirrors sit in the
    // first shape, `data/mirrors/<zone>/<ledger>` (WP-7.7).
    let mirrors = upgrade.volume.join("data/mirrors");
    let url_shaped = |root: &Path| -> Vec<String> {
        std::fs::read_dir(root)
            .map(|entries| {
                entries
                    .flatten()
                    .map(|entry| entry.file_name().to_string_lossy().into_owned())
                    .filter(|name| {
                        !(name.len() == 32 && name.chars().all(|c| c.is_ascii_hexdigit()))
                    })
                    .collect()
            })
            .unwrap_or_default()
    };
    assert!(
        !url_shaped(&mirrors).is_empty(),
        "the baseline mirrored over a URL"
    );

    // The first start migrates what it can itself, removes the URL mirrors, mirrors its own
    // Control Plane in-process under this Host's authority, and answers as the baseline did.
    let server = upgrade.start().expect("the upgraded server starts");
    answers_as_the_baseline(&upgrade);
    server.stop();
    assert!(
        url_shaped(&mirrors).is_empty(),
        "the URL mirrors are gone: {:?}",
        url_shaped(&mirrors)
    );
    assert_eq!(
        std::fs::read_dir(&mirrors)
            .expect("the mirrors root")
            .count(),
        1,
        "one authority, this Host's own"
    );

    // The legacy event history, once its shipper sent it, is archived offline: the production
    // path, which declares the backup. The shipper runs on its own schedule and says nothing when
    // the journal is empty, so a history not yet sent gets the server back for a few more rounds.
    let archive = || {
        upgrade.offline(&[
            "migrate",
            "events",
            "--volume",
            upgrade.volume(),
            "--backup",
            "the test's copy of the baseline volume",
            "--config",
            upgrade.config.to_str().expect("UTF-8"),
        ])
    };
    // It is archived only once older than the archive's horizon, a day and some past the capture.
    // The capture is fixed in the past, so every run from then on takes the whole path; a run
    // inside that first day can only prove the refusal, and stops there.
    let captured = captured()["captured_at"]
        .as_u64()
        .expect("the capture's time");
    let drained_at = std::time::UNIX_EPOCH
        + Duration::from_secs(captured)
        + ARCHIVE_HORIZON
        + Duration::from_secs(60);
    if std::time::SystemTime::now() < drained_at {
        let refused = archive();
        assert!(!refused.status.success(), "archived inside the horizon");
        assert!(
            text(&refused).contains("a loaded window may still read"),
            "{}",
            text(&refused)
        );
        eprintln!(
            "the capture is inside the archive's horizon until {drained_at:?}: the refusal is \
             proven, the rest waits for it"
        );
        return;
    }
    // Until the shipper sent it the history is refused as undrained, and the server comes back for
    // a few more rounds; once drained, it is refused while the Control Plane's store sits inside
    // it, naming the store, until the operator moves the store out.
    let mut moved = false;
    let mut archived = archive();
    for _ in 0..6 {
        if archived.status.success() {
            break;
        }
        if text(&archived).contains("move them out of it") {
            assert!(!moved, "{}", text(&archived));
            assert!(
                text(&archived).contains("store/CURSOR_KEY"),
                "{}",
                text(&archived)
            );
            upgrade.move_the_event_store_out();
            moved = true;
        } else {
            assert!(
                text(&archived).contains("a loaded window may still read"),
                "{}",
                text(&archived)
            );
            let server = upgrade.start().expect("the upgraded server starts");
            std::thread::sleep(Duration::from_secs(5));
            server.stop();
        }
        archived = archive();
    }
    assert!(moved, "the store inside the history was never refused");
    assert!(archived.status.success(), "{}", text(&archived));

    let status = upgrade.offline(&["migrate", "status", "--volume", upgrade.volume()]);
    assert!(status.status.success(), "{}", text(&status));
    let status = text(&status);
    for subsystem in SUBSYSTEMS {
        assert!(
            status.lines().any(
                |line| line.starts_with(&format!("{subsystem}:")) && line.contains("committed")
            ),
            "{subsystem} is not committed:\n{status}"
        );
    }

    // The rollback horizon ends where the operator ends it.
    for subsystem in SUBSYSTEMS {
        let finalized = upgrade.offline(&[
            "migrate",
            "finalize",
            "--volume",
            upgrade.volume(),
            "--subsystem",
            subsystem,
        ]);
        assert!(
            finalized.status.success(),
            "{subsystem}: {}",
            text(&finalized)
        );
    }
    let status = text(&upgrade.offline(&["migrate", "status", "--volume", upgrade.volume()]));
    assert_eq!(
        status
            .lines()
            .filter(|line| line.contains("(idle)"))
            .count(),
        SUBSYSTEMS.len(),
        "{status}"
    );
    for legacy in [
        "operations/audit",
        "operations/keys/operations",
        "operations/keys/control",
        "operations/keys/data",
        "data/decisions/spool",
    ] {
        assert!(
            !upgrade.volume.join(legacy).exists(),
            "{legacy} outlived its finalize"
        );
    }

    let verified = upgrade.offline(&["volume", "verify", "--volume", upgrade.volume()]);
    assert!(verified.status.success(), "{}", text(&verified));
    assert!(
        text(&verified).contains(" 0 findings"),
        "{}",
        text(&verified)
    );
    let audited = upgrade.offline(&[
        "audit",
        "verify",
        "--directory",
        upgrade
            .volume
            .join("host/audit/legacy")
            .to_str()
            .expect("UTF-8"),
    ]);
    assert!(audited.status.success(), "{}", text(&audited));
    assert!(
        text(&audited).contains("legacy chain verified"),
        "{}",
        text(&audited)
    );

    // And the migrated volume serves as the baseline's did.
    let server = upgrade.start().expect("the migrated server starts again");
    answers_as_the_baseline(&upgrade);
    server.stop();
}
