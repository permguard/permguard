// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The first administrator, end to end (WP-8.2): a fresh Host starts, waits with a setup code in
//! a private file of its volume and never in its log, makes the first administrator with it over
//! `/auth/v1/setup`, and then the route is gone.

#![allow(clippy::expect_used)]

use std::io::Read as _;
use std::process::Command;

fn binary() -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_permguard-all-in-one"));
    for (name, _) in std::env::vars_os() {
        if name.to_string_lossy().starts_with("PERMGUARD_") {
            command.env_remove(name);
        }
    }
    command
}

/// The status and body of one request with curl.
fn curl(method: &str, url: &str, body: Option<&str>) -> (u16, String) {
    let mut command = Command::new("curl");
    command.args([
        "-sS",
        "--max-time",
        "10",
        "-X",
        method,
        "-w",
        "\n%{http_code}",
    ]);
    if let Some(body) = body {
        command.args(["-H", "content-type: application/json", "--data", body]);
    }
    let output = command.arg(url).output().expect("curl runs");
    let text = String::from_utf8_lossy(&output.stdout).into_owned();
    let (body, status) = text.rsplit_once('\n').unwrap_or(("", "0"));
    (status.trim().parse().unwrap_or(0), body.to_owned())
}

fn find(dir: &std::path::Path, tail: &[&str]) -> Option<std::path::PathBuf> {
    for entry in std::fs::read_dir(dir).ok()?.flatten() {
        let path = entry.path();
        if path.is_dir() {
            if let Some(found) = find(&path, tail) {
                return Some(found);
            }
        } else if path.ends_with(tail.iter().collect::<std::path::PathBuf>()) {
            return Some(path);
        }
    }
    None
}

#[test]
fn a_fresh_host_makes_its_first_administrator_with_the_setup_code_once() {
    let dir = std::env::temp_dir().join(format!("permguard-first-admin-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("the scratch directory is created");
    std::fs::write(
        dir.join("config.yml"),
        concat!(
            "development_mode: true\nautogenerate: true\nassurance:\n  profile: development\n",
            "log:\n  level: info\n  format: json\n",
            "host:\n  addr: 127.0.0.1:0\n",
            "runtime:\n  planes: []\n",
        ),
    )
    .expect("the config writes");

    let mut child = binary()
        .arg(dir.join("config.yml"))
        .env("PERMGUARD_WORKING_DIR", &dir)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("the runtime starts");
    let mut stdout = child.stdout.take().expect("stdout is piped");
    let mut seen = String::new();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    let mut buffer = [0u8; 4096];
    while std::time::Instant::now() < deadline
        && !(seen.contains("server.started") && seen.contains("telemetry.listening"))
    {
        match stdout.read(&mut buffer) {
            Ok(0) => break,
            Ok(read) => seen.push_str(&String::from_utf8_lossy(&buffer[..read])),
            Err(_) => break,
        }
    }
    let address = seen
        .lines()
        .filter(|line| line.contains("telemetry.listening"))
        .find_map(|line| {
            let (_, rest) = line.split_once("\"address\":\"")?;
            let (address, _) = rest.split_once('"')?;
            Some(address.to_owned())
        });
    let code_file = find(&dir, &["host", "setup", "code"]);

    let outcome = (|| {
        let address = address.ok_or("no telemetry address")?;
        let code_file = code_file.ok_or("no code file")?;
        let code = std::fs::read_to_string(&code_file)
            .map_err(|error| error.to_string())?
            .trim()
            .to_owned();
        let url = format!("http://{address}/auth/v1/setup");
        let waiting = curl("GET", &url, None);
        let wrong = curl(
            "POST",
            &url,
            Some(r#"{"code":"pgsetup_wrong","name":"mallory","email":"m@evil.example"}"#),
        );
        let made = curl(
            "POST",
            &url,
            Some(&format!(
                r#"{{"code":"{code}","name":"alice","password":"alice's first password"}}"#
            )),
        );
        let after = curl("GET", &url, None);
        Ok::<_, String>((code, waiting, wrong, made, after))
    })();

    let _ = child.kill();
    let _ = child.wait();
    let (code, waiting, wrong, made, after) =
        outcome.unwrap_or_else(|reason| panic!("{reason}: {seen}"));

    assert!(seen.contains("host.setup_waiting"), "{seen}");
    assert!(!seen.contains(&code), "the code never reaches the log");
    assert_eq!(waiting.0, 200, "{}", waiting.1);
    assert!(waiting.1.contains("\"waiting\":true"), "{}", waiting.1);
    assert_eq!(wrong.0, 401, "{}", wrong.1);
    assert_eq!(made.0, 201, "{}", made.1);
    assert!(
        made.1.contains("\"principal\":\"user:alice\""),
        "{}",
        made.1
    );
    assert_eq!(after.0, 404, "the route is gone: {}", after.1);
}
