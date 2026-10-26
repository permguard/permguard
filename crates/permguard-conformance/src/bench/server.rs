// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The server under measurement: the release's own `permguard-all-in-one`, started on loopback with
//! a configuration written for the run, and the example dataset applied to it with the release's own
//! `permguard` CLI — the path an operator takes, not a shortcut into the planes' internals.

use std::collections::BTreeMap;
use std::io::Read as _;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::time::{Duration, Instant};

use serde::Deserialize;
use sha2::{Digest as _, Sha256};

use super::report::{Dataset, Expected, Workload};

/// The zone and ledger the dataset is applied to.
pub const ZONE: &str = "bench";
pub const LEDGER: &str = "main";

/// The evidence modes a Data Plane accepts: no decision log, or a durable record before every
/// answer. (`open`, deciding unrecorded when the spool is full, is refused by the configuration.)
pub const EVIDENCE_MODES: [&str; 2] = ["disabled", "required"];

/// The binaries a run drives.
#[derive(Debug, Clone)]
pub struct Binaries {
    pub server: PathBuf,
    pub cli: PathBuf,
}

/// A running server, stopped when dropped.
pub struct Server {
    child: Child,
    pub data_http: String,
    pub data_grpc: String,
    pub control: String,
    pub host: String,
    pub directory: PathBuf,
    log: PathBuf,
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Server {
    /// The server's process id.
    pub fn pid(&self) -> u32 {
        self.child.id()
    }

    /// The last lines the server logged: what a failed run reports.
    pub fn log_tail(&self) -> String {
        let text = std::fs::read_to_string(&self.log).unwrap_or_default();
        let lines: Vec<&str> = text.lines().collect();
        lines[lines.len().saturating_sub(20)..].join("\n")
    }
}

/// A free loopback port. The port is released before the server binds it, so another process could
/// take it in between; the server then fails to start, which the run reports, rather than measuring
/// the wrong thing.
fn free_port() -> std::io::Result<u16> {
    Ok(TcpListener::bind("127.0.0.1:0")?.local_addr()?.port())
}

/// The configuration the run writes: the development profile on loopback, every listener in the
/// clear, the catalog and decisions open to the run, and the evidence mode the run asks for. The
/// capacity settings travel as environment, by the names the report records.
pub fn configuration(ports: (u16, u16, u16), evidence: &str) -> String {
    let (host, control, data) = ports;
    // The Control Plane stores decision batches only from a Data Plane that ships them.
    let store = if evidence == "required" {
        "true"
    } else {
        "false"
    };
    let log = match evidence {
        "required" => format!(
            concat!(
                "    log:\n",
                "      enabled: \"true\"\n",
                "      server: {{ url: \"http://127.0.0.1:{control}\" }}\n",
                "      spool: {{ directory: \"data/decisions/spool\", bytes: \"256M\", age: \"24h\" }}\n",
                "      batch: {{ bytes: \"256k\", interval: \"1s\" }}\n",
                "      mode: \"required\"\n",
                "      sample: {{ permits: \"1.0\" }}\n",
                "      include: {{ subject_properties: [], resource_properties: [], context: [] }}\n",
            ),
            control = control
        ),
        _ => "    log: { enabled: \"false\" }\n".to_owned(),
    };
    format!(
        concat!(
            "development_mode: true\n",
            "autogenerate: true\n",
            "assurance: {{ profile: development }}\n",
            "log: {{ level: warn, format: json }}\n",
            "host:\n",
            "  addr: 127.0.0.1:{host}\n",
            "  authz:\n",
            "    public:\n",
            "      - {{ operations: [catalog.read, catalog.write, policy.push], selector: \"plane/control/*\" }}\n",
            "      - {{ operations: [decision.evaluate], selector: \"plane/data/*\" }}\n",
            "runtime: {{ planes: [control, data] }}\n",
            "controlPlane:\n",
            "  public:\n",
            "    http: {{ enabled: true, addr: 127.0.0.1:{control} }}\n",
            "    grpc: {{ enabled: true, addr: 127.0.0.1:{control} }}\n",
            "  decisions: {{ enabled: \"{store}\", directory: \"data/decisions/store\", retention: \"7d\" }}\n",
            "dataPlane:\n",
            "  public:\n",
            "    http: {{ enabled: true, addr: 127.0.0.1:{data} }}\n",
            "    grpc: {{ enabled: true, addr: 127.0.0.1:{data} }}\n",
            "  mirrors:\n",
            "    enabled: \"true\"\n",
            "    interval: \"1s\"\n",
            "    servers: [{{ url: \"http://127.0.0.1:{control}\" }}]\n",
            "  decisions:\n",
            "{log}",
            "operations:\n",
            "  keys: {{ enabled: true, publish_ahead: 5m, rotate_every: 1h, retain: 1d }}\n",
            "  secrets: {{ provider: directory, coordinator_root_ref: zone-root }}\n",
            "  audit:\n",
            "    sink: file\n",
            "    retention: 7d\n",
            "    pseudonym: {{ enabled: true, key_ref: audit-pseudonym, key_version: \"v1\" }}\n",
        ),
        host = host,
        control = control,
        data = data,
        store = store,
        log = log,
    )
}

/// The settings every run passes, before its own: every client of the benchmark connects from
/// loopback, so the per-address connection bound would cap the ladder at its value and the rungs
/// past it would measure that bound instead of the plane's. A run's `--set` overrides them.
pub fn defaults() -> [(&'static str, &'static str); 1] {
    [("PERMGUARD_LIMITS_CONNECTIONS_PER_PEER", "0")]
}

/// The binary, without the `PERMGUARD_*` variables of the shell that runs the benchmark: the server
/// refuses one it does not read, and a stray export is not what a benchmark measures.
fn command(binary: &Path) -> Command {
    let mut command = Command::new(binary);
    for (name, _) in std::env::vars_os() {
        if name.to_string_lossy().starts_with("PERMGUARD_") {
            command.env_remove(name);
        }
    }
    command
}

/// Starts the server in `directory` for `evidence`, with `settings` as environment, and waits until
/// it is ready.
pub fn start(
    binaries: &Binaries,
    directory: &Path,
    evidence: &str,
    settings: &BTreeMap<String, String>,
) -> Result<Server, String> {
    let _ = std::fs::remove_dir_all(directory);
    std::fs::create_dir_all(directory).map_err(|error| error.to_string())?;
    let ports = (
        free_port().map_err(|error| error.to_string())?,
        free_port().map_err(|error| error.to_string())?,
        free_port().map_err(|error| error.to_string())?,
    );
    let config = directory.join("config.yml");
    std::fs::write(&config, configuration(ports, evidence)).map_err(|error| error.to_string())?;
    let log = directory.join("server.log");
    let stdout = std::fs::File::create(&log).map_err(|error| error.to_string())?;
    let stderr = stdout.try_clone().map_err(|error| error.to_string())?;
    let child = command(&binaries.server)
        .arg(&config)
        .env("PERMGUARD_WORKING_DIR", directory.join("volume"))
        .envs(defaults().iter().map(|(name, value)| (*name, *value)))
        .envs(settings)
        .stdout(stdout)
        .stderr(stderr)
        .spawn()
        .map_err(|error| format!("starting {}: {error}", binaries.server.display()))?;
    let mut server = Server {
        child,
        data_http: format!("http://127.0.0.1:{}", ports.2),
        data_grpc: format!("grpc://127.0.0.1:{}", ports.2),
        control: format!("http://127.0.0.1:{}", ports.1),
        host: format!("127.0.0.1:{}", ports.0),
        directory: directory.to_path_buf(),
        log,
    };
    wait_ready(&mut server, Duration::from_secs(120))?;
    Ok(server)
}

/// Waits until the Host answers `/readyz` with `200`.
fn wait_ready(server: &mut Server, within: Duration) -> Result<(), String> {
    let deadline = Instant::now() + within;
    while Instant::now() < deadline {
        if let Ok(Some(status)) = server.child.try_wait() {
            return Err(format!(
                "the server exited ({status}) before it was ready:\n{}",
                server.log_tail()
            ));
        }
        if let Ok(200) = get_status(&server.host, "/readyz") {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    Err(format!(
        "the server was not ready within {within:?}:\n{}",
        server.log_tail()
    ))
}

/// The server's metrics, as its Host publishes them.
pub fn metrics(server: &Server) -> Result<String, String> {
    use std::io::Write as _;
    let mut stream =
        std::net::TcpStream::connect(&server.host).map_err(|error| error.to_string())?;
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .map_err(|error| error.to_string())?;
    write!(
        stream,
        "GET /metrics HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
        server.host
    )
    .map_err(|error| error.to_string())?;
    let mut answer = String::new();
    stream
        .read_to_string(&mut answer)
        .map_err(|error| error.to_string())?;
    let (head, body) = answer
        .split_once("\r\n\r\n")
        .ok_or("the metrics answer has no body")?;
    if !head.starts_with("HTTP/1.1 200") {
        return Err(format!(
            "the metrics answered {}",
            head.lines().next().unwrap_or_default()
        ));
    }
    Ok(body.to_owned())
}

/// The status of a plain `GET` on loopback.
fn get_status(address: &str, path: &str) -> std::io::Result<u16> {
    use std::io::Write as _;
    let mut stream = std::net::TcpStream::connect(address)?;
    stream.set_read_timeout(Some(Duration::from_secs(2)))?;
    write!(
        stream,
        "GET {path} HTTP/1.1\r\nHost: {address}\r\nConnection: close\r\n\r\n"
    )?;
    let mut head = String::new();
    let _ = stream.read_to_string(&mut head);
    head.split_whitespace()
        .nth(1)
        .and_then(|status| status.parse().ok())
        .ok_or_else(|| std::io::Error::other("no status line"))
}

/// Runs the CLI, with its configuration in the run's directory rather than the user's.
fn cli(binaries: &Binaries, directory: &Path, args: &[&str]) -> Result<String, String> {
    let output = command(&binaries.cli)
        .args(args)
        .env("PERMGUARD_CONFIG", directory.join("cli.yml"))
        .output()
        .map_err(|error| format!("running {}: {error}", binaries.cli.display()))?;
    if output.status.success() {
        Ok(String::from_utf8_lossy(&output.stdout).into_owned())
    } else {
        Err(format!(
            "`permguard {}` failed: {}{}",
            args.join(" "),
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        ))
    }
}

/// Applies the example at `example` to the server's Control Plane, as `bench/main`.
pub fn apply(
    binaries: &Binaries,
    server: &Server,
    example: &Path,
    languages: &str,
) -> Result<(), String> {
    let endpoint = server.control.clone();
    let directory = &server.directory;
    cli(
        binaries,
        directory,
        &["--control-endpoint", &endpoint, "zones", "create", ZONE],
    )?;
    cli(
        binaries,
        directory,
        &[
            "--control-endpoint",
            &endpoint,
            "ledgers",
            "create",
            LEDGER,
            "--zone",
            ZONE,
        ],
    )?;
    let workspace = directory.join("workspace");
    copy_tree(example, &workspace).map_err(|error| error.to_string())?;
    let _ = std::fs::remove_dir_all(workspace.join(".permguard"));
    let workspace_arg = workspace.to_string_lossy().into_owned();
    let w = |rest: &[&str]| -> Vec<String> {
        let mut args = vec!["-w".to_owned(), workspace_arg.clone()];
        args.extend(rest.iter().map(|arg| (*arg).to_owned()));
        args
    };
    for args in [
        w(&["init", LEDGER, "--language", languages]),
        w(&["remote", "add", "origin", &endpoint]),
        w(&["checkout", &format!("origin/{ZONE}/{LEDGER}")]),
        w(&["apply", "-m", "the benchmark's dataset"]),
    ] {
        let args: Vec<&str> = args.iter().map(String::as_str).collect();
        cli(binaries, directory, &args)?;
    }
    Ok(())
}

fn copy_tree(from: &Path, to: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(to)?;
    for entry in std::fs::read_dir(from)? {
        let entry = entry?;
        let target = to.join(entry.file_name());
        if entry.file_type()?.is_dir() {
            copy_tree(&entry.path(), &target)?;
        } else {
            std::fs::copy(entry.path(), &target)?;
        }
    }
    Ok(())
}

/// A case of the example's `tests/*.yml`, as far as the benchmark reads it.
#[derive(Debug, Deserialize)]
struct Case {
    request: String,
    #[serde(default)]
    profile: Option<String>,
    expect: Expect,
}

#[derive(Debug, Deserialize)]
struct Expect {
    #[serde(default)]
    decision: Option<String>,
    #[serde(default)]
    error: Option<String>,
    #[serde(default)]
    evaluations: Option<serde_json::Value>,
}

/// The manifest's profiles and partitions, as far as the benchmark reads them.
#[derive(Debug, Deserialize)]
struct Manifest {
    partitions: BTreeMap<String, Partition>,
    profiles: BTreeMap<String, Profile>,
}

#[derive(Debug, Deserialize)]
struct Partition {
    runtime: String,
}

#[derive(Debug, Deserialize)]
struct Profile {
    partitions: Vec<String>,
}

/// The dataset an example makes: its digest, and per profile the single requests its own tests
/// expect a decision of — not a list kept here, which could drift from what the example claims.
pub fn dataset(example: &Path, name: &str) -> Result<Dataset, String> {
    let manifest: Manifest = serde_norway::from_str(
        &std::fs::read_to_string(example.join("manifest.yml"))
            .map_err(|error| error.to_string())?,
    )
    .map_err(|error| format!("manifest.yml: {error}"))?;
    let mut workloads: BTreeMap<(String, bool), Vec<Expected>> = BTreeMap::new();
    let mut tests: Vec<PathBuf> = std::fs::read_dir(example.join("tests"))
        .map_err(|error| error.to_string())?
        .filter_map(|entry| entry.ok().map(|entry| entry.path()))
        .filter(|path| path.extension().is_some_and(|ext| ext == "yml"))
        .collect();
    tests.sort();
    for file in tests {
        let cases: Vec<Case> = serde_norway::from_str(
            &std::fs::read_to_string(&file).map_err(|error| error.to_string())?,
        )
        .map_err(|error| format!("{}: {error}", file.display()))?;
        for case in cases {
            // A decision with a verdict, single or a batch; an expected error is not a load.
            let decision = match (&case.expect.decision, &case.expect.error) {
                (Some(decision), None) => decision == "permit",
                _ => continue,
            };
            let boxcarred = case.expect.evaluations.is_some();
            let request = example.join("tests").join(&case.request);
            let body: serde_json::Value = serde_json::from_str(
                &std::fs::read_to_string(&request).map_err(|error| error.to_string())?,
            )
            .map_err(|error| format!("{}: {error}", request.display()))?;
            let profile = case
                .profile
                .clone()
                .or_else(|| body["profile"].as_str().map(str::to_owned))
                .unwrap_or_else(|| "default".to_owned());
            workloads
                .entry((profile, boxcarred))
                .or_default()
                .push(Expected {
                    file: normalize(&case.request),
                    decision,
                });
        }
    }
    let workloads = workloads
        .into_iter()
        .map(|((profile, boxcarred), requests)| {
            let mut runtimes: Vec<String> = manifest
                .profiles
                .get(&profile)
                .map(|declared| {
                    declared
                        .partitions
                        .iter()
                        .filter_map(|partition| manifest.partitions.get(partition))
                        .map(|partition| partition.runtime.clone())
                        .collect()
                })
                .unwrap_or_default();
            runtimes.sort();
            runtimes.dedup();
            Workload {
                name: if boxcarred {
                    format!("{profile} boxcarred")
                } else {
                    profile.clone()
                },
                profile,
                boxcarred,
                runtimes,
                requests,
            }
        })
        .collect();
    Ok(Dataset {
        name: name.to_owned(),
        digest: digest(example).map_err(|error| error.to_string())?,
        workloads,
    })
}

/// `tests/<request>` relative to the example, with `..` resolved.
fn normalize(request: &str) -> String {
    let mut parts: Vec<&str> = vec!["tests"];
    for part in request.split('/') {
        match part {
            ".." => {
                parts.pop();
            }
            "." | "" => {}
            other => parts.push(other),
        }
    }
    parts.join("/")
}

/// `sha256:` over every file under `root`, each as its relative path, a NUL, its length and its
/// bytes, in path order.
pub fn digest(root: &Path) -> std::io::Result<String> {
    fn walk(dir: &Path, files: &mut Vec<PathBuf>) -> std::io::Result<()> {
        for entry in std::fs::read_dir(dir)? {
            let path = entry?.path();
            if path.is_dir() {
                if path.file_name().is_some_and(|name| name == ".permguard") {
                    continue;
                }
                walk(&path, files)?;
            } else {
                files.push(path);
            }
        }
        Ok(())
    }
    let mut files = Vec::new();
    walk(root, &mut files)?;
    files.sort();
    let mut hasher = Sha256::new();
    for file in files {
        let relative = file.strip_prefix(root).unwrap_or(&file);
        let bytes = std::fs::read(&file)?;
        hasher.update(relative.to_string_lossy().as_bytes());
        hasher.update([0]);
        hasher.update((bytes.len() as u64).to_be_bytes());
        hasher.update(&bytes);
    }
    Ok(format!(
        "sha256:{}",
        hasher
            .finalize()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    ))
}
