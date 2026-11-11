// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The first administrator, end to end: a fresh all-in-one running the Authority Plane makes the
//! service account `admin` at its first start, its access key and secret key in a file of the
//! volume only its owner reads and never in the log; the key obtains a token at the token
//! endpoint, and the token administers the service accounts. A second start makes nothing new.

#![allow(clippy::expect_used)]

use std::io::Read as _;
use std::process::{Child, Command};

fn binary() -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_permguard-all-in-one"));
    for (name, _) in std::env::vars_os() {
        if name.to_string_lossy().starts_with("PERMGUARD_") {
            command.env_remove(name);
        }
    }
    command
}

/// The status and body of one request with curl, its extra arguments before the URL.
fn curl(method: &str, url: &str, extra: &[&str]) -> (u16, String) {
    let output = Command::new("curl")
        .args([
            "-sS",
            "--max-time",
            "10",
            "-X",
            method,
            "-w",
            "\n%{http_code}",
        ])
        .args(extra)
        .arg(url)
        .output()
        .expect("curl runs");
    let text = String::from_utf8_lossy(&output.stdout).into_owned();
    let (body, status) = text.rsplit_once('\n').unwrap_or(("", "0"));
    (status.trim().parse().unwrap_or(0), body.to_owned())
}

/// A loopback port nothing listens on now.
fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .and_then(|listener| listener.local_addr())
        .map(|address| address.port())
        .expect("a free port")
}

/// Starts the runtime on `dir` and reads its log until it serves: the child and what it logged.
fn start(dir: &std::path::Path) -> (Child, String) {
    let mut child = binary()
        .arg(dir.join("config.yml"))
        .env("PERMGUARD_WORKING_DIR", dir)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("the runtime starts");
    let mut stdout = child.stdout.take().expect("stdout is piped");
    let mut seen = String::new();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    let mut buffer = [0u8; 4096];
    while std::time::Instant::now() < deadline && !seen.contains("server.started") {
        match stdout.read(&mut buffer) {
            Ok(0) => break,
            Ok(read) => seen.push_str(&String::from_utf8_lossy(&buffer[..read])),
            Err(_) => break,
        }
    }
    (child, seen)
}

fn stop(mut child: Child) {
    let _ = child.kill();
    let _ = child.wait();
}

#[test]
fn a_fresh_host_makes_its_administrator_once_and_its_key_administers() {
    let dir = std::env::temp_dir().join(format!("permguard-first-admin-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("the scratch directory is created");
    let port = free_port();
    std::fs::write(
        dir.join("config.yml"),
        format!(
            "development_mode: true\nautogenerate: true\nassurance:\n  profile: development\n\
             log:\n  level: info\n  format: json\n\
             host:\n  addr: 127.0.0.1:0\n\
             runtime:\n  planes: [authority]\n\
             authority:\n  url: http://127.0.0.1:{port}\n\
             authorityPlane:\n  public:\n    http: {{ addr: 127.0.0.1:{port} }}\n"
        ),
    )
    .expect("the config writes");

    let (child, seen) = start(&dir);
    let key_file = dir.join("planes/authority/admin.key");
    let base = format!("http://127.0.0.1:{port}");
    let outcome = (|| {
        let text = std::fs::read_to_string(&key_file).map_err(|error| error.to_string())?;
        let field = |name: &str| {
            text.lines()
                .find_map(|line| line.strip_prefix(name).map(str::trim).map(str::to_owned))
                .ok_or(format!("no {name} in the key file"))
        };
        let (access_key, secret_key) = (field("access_key:")?, field("secret_key:")?);
        let refused = curl(
            "POST",
            &format!("{base}/authority/v1/token"),
            &[
                "-u",
                &format!("{access_key}:pgsk_wrong"),
                "--data",
                "grant_type=client_credentials",
            ],
        );
        let issued = curl(
            "POST",
            &format!("{base}/authority/v1/token"),
            &[
                "-u",
                &format!("{access_key}:{secret_key}"),
                "--data",
                "grant_type=client_credentials",
            ],
        );
        let token = issued
            .1
            .split_once("\"access_token\":\"")
            .and_then(|(_, rest)| rest.split_once('"'))
            .map(|(token, _)| token.to_owned())
            .ok_or(format!("no token: {}", issued.1))?;
        let accounts = curl(
            "GET",
            &format!("{base}/authority/v1/service-accounts"),
            &["-H", &format!("authorization: Bearer {token}")],
        );
        let anonymous = curl("GET", &format!("{base}/authority/v1/service-accounts"), &[]);
        Ok::<_, String>((access_key, secret_key, refused, issued, accounts, anonymous))
    })();
    stop(child);
    let (access_key, secret_key, refused, issued, accounts, anonymous) =
        outcome.unwrap_or_else(|reason| panic!("{reason}: {seen}"));

    assert!(seen.contains("authority.admin_created"), "{seen}");
    assert!(seen.contains(&access_key), "the log names the access key");
    assert!(
        !seen.contains(&secret_key),
        "the secret key never reaches the log"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = std::fs::metadata(&key_file)
            .expect("the key file")
            .permissions()
            .mode();
        assert_eq!(mode & 0o077, 0, "the key file is its owner's alone");
    }
    assert_eq!(refused.0, 401, "{}", refused.1);
    assert_eq!(issued.0, 200, "{}", issued.1);
    assert!(
        issued.1.contains("\"token_type\":\"Bearer\""),
        "{}",
        issued.1
    );
    assert_eq!(accounts.0, 200, "{}", accounts.1);
    assert!(accounts.1.contains("\"name\":\"admin\""), "{}", accounts.1);
    assert_eq!(anonymous.0, 401, "{}", anonymous.1);

    // Restarted, the administrator is the one it made: nothing new is created.
    let (child, again) = start(&dir);
    stop(child);
    assert!(again.contains("server.started"), "{again}");
    assert!(!again.contains("authority.admin_created"), "{again}");
    let text = std::fs::read_to_string(&key_file).expect("the key file stays");
    assert!(text.contains(&access_key));
    let _ = std::fs::remove_dir_all(&dir);
}
