// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! TS-5: secret material never reaches diagnostics or telemetry.
//!
//! An all-in-one runs on a fresh volume whose secrets are canaries: the zone root, the audit
//! pseudonym key, the key-encryption key of the `file` custody and the backups' recovery key, each
//! a value nothing else would ever print. The server starts, is asked about its state, is asked for
//! a decision it refuses (no ledger is served) and stops; then it is started again under a
//! configuration whose recovery key disagrees with its stated id, which it refuses. Every byte it
//! said — its log at `debug`, both refusals, `/metrics`, the process discovery document, the status
//! — and every file it wrote on the volume outside the secrets directory, the sealed keys and the
//! audit trail with its receipts included, is searched for each canary as text, in upper case,
//! decoded from hex, and in base64. That the secret type has no `Debug`, so no `{:?}` of it can
//! reach a log line, an error or a panic message, is checked at compile time.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::io::{Read as _, Write as _};
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::time::{Duration, Instant};

use base64::Engine as _;

/// The canaries, by secret reference: hex digits only, so a reader that decodes hex accepts them.
const CANARIES: [(&str, &str); 4] = [
    (
        "zone-root",
        "c0ffee0decade5ec2e7a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a",
    ),
    (
        "audit-pseudonym",
        "c0ffee0decade5ec2e7b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b",
    ),
    ("host-kek", "c0ffee0decade5ec2e7c3c3c3c3c3c3c"),
    (
        "recovery",
        "c0ffee0decade5ec2e7d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d",
    ),
];

/// Every form a canary could take on its way out.
fn forms(canary: &str) -> Vec<Vec<u8>> {
    let b64 = base64::engine::general_purpose::STANDARD;
    let url = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let decoded: Vec<u8> = (0..canary.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(&canary[at..at + 2], 16).expect("hex"))
        .collect();
    vec![
        canary.as_bytes().to_vec(),
        canary.to_ascii_uppercase().into_bytes(),
        // The distinctive prefix alone, so a truncated value is caught as well.
        canary.as_bytes()[..20].to_vec(),
        decoded.clone(),
        b64.encode(canary).into_bytes(),
        url.encode(canary).into_bytes(),
        b64.encode(&decoded).into_bytes(),
        url.encode(&decoded).into_bytes(),
    ]
}

/// Where `haystack` holds a form of a canary: the secret's reference, or `None`.
fn leaked(haystack: &[u8]) -> Option<&'static str> {
    CANARIES.iter().find_map(|(name, canary)| {
        forms(canary)
            .iter()
            .any(|form| {
                haystack
                    .windows(form.len())
                    .any(|window| window == form.as_slice())
            })
            .then_some(*name)
    })
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

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .expect("a port")
        .local_addr()
        .expect("an address")
        .port()
}

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
    (status, answer)
}

fn get(port: u16, path: &str) -> (u16, String) {
    exchange(
        port,
        &format!("GET {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n"),
    )
}

/// A fresh volume with canary secrets, and its configuration.
struct Canaried {
    dir: PathBuf,
    volume: PathBuf,
    config: PathBuf,
    host: u16,
    data: u16,
}

impl Canaried {
    fn new() -> Self {
        let dir = std::env::temp_dir().join(format!("permguard-canaries-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let volume = dir.join("volume");
        let secrets = volume.join("operations/secrets");
        std::fs::create_dir_all(&secrets).expect("the secrets directory");
        for (name, canary) in CANARIES {
            std::fs::write(secrets.join(name), canary).expect("a secret");
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            for path in [volume.clone(), volume.join("operations"), secrets.clone()] {
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700))
                    .expect("owner-only");
            }
            for (name, _) in CANARIES {
                std::fs::set_permissions(
                    secrets.join(name),
                    std::fs::Permissions::from_mode(0o600),
                )
                .expect("owner-only");
            }
        }
        let canaried = Self {
            config: dir.join("config.yml"),
            volume,
            dir,
            host: free_port(),
            data: free_port(),
        };
        canaried.configure(None);
        canaried
    }

    /// The deployment: both Planes, the `file` custody under the canary key-encryption key, the
    /// pseudonym and the zone root from the store, the recovery key by reference — and, when
    /// `stated` is given, a recovery-key id that is not the key's.
    fn configure(&self, stated: Option<&str>) {
        let (control, data) = (free_port(), self.data);
        let stated = stated
            .map(|id| format!("    recovery_key_id: \"{id}\"\n"))
            .unwrap_or_default();
        std::fs::write(
            &self.config,
            format!(
                "working_dir: {volume}
development_mode: true
autogenerate: true
assurance: {{ profile: development }}
log: {{ level: debug, format: json }}
host:
  addr: 127.0.0.1:{host}
  authz:
    public:
      - {{ operations: [decision.evaluate], selector: \"plane/data/*\" }}
runtime: {{ planes: [control, data] }}
controlPlane:
  public:
    http: {{ enabled: true, addr: 127.0.0.1:{control} }}
    grpc: {{ enabled: true, addr: 127.0.0.1:{control} }}
dataPlane:
  public:
    http: {{ enabled: true, addr: 127.0.0.1:{data} }}
    grpc: {{ enabled: true, addr: 127.0.0.1:{data} }}
  mirrors:
    enabled: \"true\"
    interval: 1s
operations:
  keys: {{ enabled: true, publish_ahead: 5m, rotate_every: 1h, retain: 1d, custody: file, kek_ref: host-kek }}
  secrets: {{ provider: directory, coordinator_root_ref: zone-root, zone_key_version: \"v1\" }}
  audit:
    pseudonym: {{ enabled: true, key_ref: audit-pseudonym, key_version: \"v1\" }}
  backup:
    recovery_key: recovery
{stated}    encryption_profile: aes-256-gcm
    retention: 90d
    destruction: DESTROY-2026-01
",
                volume = self.volume.display(),
                host = self.host,
            ),
        )
        .expect("the configuration writes");
    }

    /// Starts the server and waits until it is ready; panics with its log otherwise.
    fn start(&self, log: &Path) -> Child {
        let out = std::fs::File::create(log).expect("a log");
        let mut child = binary()
            .arg(&self.config)
            .stdout(out.try_clone().expect("a handle"))
            .stderr(out)
            .spawn()
            .expect("the server starts");
        let deadline = Instant::now() + Duration::from_secs(90);
        while Instant::now() < deadline {
            if let Ok(Some(_)) = child.try_wait() {
                panic!(
                    "the server exited:\n{}",
                    std::fs::read_to_string(log).unwrap_or_default()
                );
            }
            if get(self.host, "/readyz").0 == 200 {
                return child;
            }
            std::thread::sleep(Duration::from_millis(250));
        }
        let _ = child.kill();
        let _ = child.wait();
        panic!(
            "not ready in time:\n{}",
            std::fs::read_to_string(log).unwrap_or_default()
        );
    }

    /// Every file on the volume outside the secrets directory, where the canaries were put.
    fn files(&self) -> Vec<PathBuf> {
        fn walk(path: &Path, skip: &Path, found: &mut Vec<PathBuf>) {
            for entry in std::fs::read_dir(path).expect("readable").flatten() {
                let path = entry.path();
                if path == skip {
                    continue;
                }
                let kind = entry.file_type().expect("a type");
                if kind.is_dir() {
                    walk(&path, skip, found);
                } else if kind.is_file() {
                    found.push(path);
                }
            }
        }
        let mut found = Vec::new();
        walk(
            &self.volume,
            &self.volume.join("operations/secrets"),
            &mut found,
        );
        found
    }
}

impl Drop for Canaried {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn stop(mut child: Child) {
    let _ = Command::new("kill")
        .args(["-TERM", &child.id().to_string()])
        .status();
    let deadline = Instant::now() + Duration::from_secs(30);
    while Instant::now() < deadline {
        if let Ok(Some(_)) = child.try_wait() {
            return;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    let _ = child.kill();
    let _ = child.wait();
}

#[test]
fn no_secret_reaches_a_log_an_error_a_metric_discovery_or_a_file() {
    let canaried = Canaried::new();

    // A start, the state asked for, a stop: everything said and written while serving.
    let log = canaried.dir.join("serving.log");
    let child = canaried.start(&log);
    let mut said = Vec::new();
    for path in [
        "/metrics",
        "/.well-known/server-configuration",
        "/readyz",
        "/healthz",
        "/host/v1/status",
    ] {
        let (_, answer) = get(canaried.host, path);
        said.push((path.to_owned(), answer));
    }
    let request = "{\"zone\":\"acme\",\"ledger\":\"main\",\"subject\":{\"type\":\"user\",\"id\":\"amy\"},\"resource\":{\"type\":\"doc\",\"id\":\"1\"},\"action\":{\"name\":\"read\"}}";
    let (status, answer) = exchange(
        canaried.data,
        &format!(
            "POST {} HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{request}",
            permguard_languages::request::EVALUATION_PATH,
            request.len()
        ),
    );
    assert!(
        status >= 400,
        "no ledger is served, the decision is refused: {status} {answer}"
    );
    said.push(("the refused decision".to_owned(), answer));
    stop(child);
    let (_, metrics) = &said[0];
    assert!(
        metrics.contains("# TYPE"),
        "the metrics were served: {metrics}"
    );
    let (_, discovery) = &said[1];
    assert!(
        discovery.contains("\"storage\":{\"qualification\":"),
        "discovery publishes the qualification: {discovery}"
    );
    said.push((
        "the serving log".to_owned(),
        std::fs::read_to_string(&log).expect("the log"),
    ));

    // A start refused on the recovery key: the error names its fingerprint, never the key.
    canaried.configure(Some("sha256:not-the-key"));
    let refused = binary()
        .arg(&canaried.config)
        .output()
        .expect("the server runs");
    assert!(
        !refused.status.success(),
        "a wrong recovery-key id is refused"
    );
    let error = format!(
        "{}{}",
        String::from_utf8_lossy(&refused.stdout),
        String::from_utf8_lossy(&refused.stderr)
    );
    let recovery = CANARIES[3].1;
    let fingerprint = permguard_host::operations::backup::recovery_key_id(recovery.as_bytes());
    assert!(error.contains("recovery_key_mismatch"), "{error}");
    assert!(error.contains(&fingerprint), "the id, not the key: {error}");
    said.push(("the refused start".to_owned(), error));

    for (what, text) in &said {
        assert_eq!(
            leaked(text.as_bytes()),
            None,
            "{what} holds a secret: {text}"
        );
    }
    let files = canaried.files();
    assert!(files.len() > 20, "the server wrote its volume: {files:?}");
    for path in files {
        let bytes = std::fs::read(&path).expect("readable");
        assert_eq!(
            leaked(&bytes),
            None,
            "{} holds a secret in the clear",
            path.display()
        );
    }
}

/// A secret is never formatted by `{:?}`: [`permguard_core::secrets::Secret`] implements no
/// `Debug`, which this proves at compile time rather than trusting a comment.
#[test]
fn the_secret_type_has_no_debug_form() {
    struct Probe<T>(std::marker::PhantomData<T>);
    trait NoDebug {
        const DEBUG: bool = false;
    }
    impl<T> NoDebug for Probe<T> {}
    impl<T: std::fmt::Debug> Probe<T> {
        #[allow(dead_code)]
        const DEBUG: bool = true;
    }
    const { assert!(!<Probe<permguard_core::secrets::Secret>>::DEBUG) };
    // The probe tells a Debug type apart.
    const { assert!(<Probe<String>>::DEBUG) };
}

/// The canary search finds each form it claims to: a check that passes because it looks for
/// nothing proves nothing.
#[test]
fn the_canary_search_finds_every_form() {
    for (name, canary) in CANARIES {
        for form in forms(canary) {
            let mut text = b"before ".to_vec();
            text.extend_from_slice(&form);
            text.extend_from_slice(b" after");
            assert_eq!(leaked(&text), Some(name));
        }
    }
    assert_eq!(leaked(b"nothing secret here"), None);
}
