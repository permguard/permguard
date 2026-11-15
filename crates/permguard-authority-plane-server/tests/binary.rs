// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The `permguard-authority-plane` binary (`2-security/8` Where it runs): it names its product,
//! and started with `runtime.planes: [authority]` it serves the Authority Plane alone, making
//! `admin` at its first start and issuing a token with its key, as the all-in-one does.

#![allow(clippy::expect_used)]

use std::io::Read as _;
use std::process::{Child, Command};

fn binary() -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_permguard-authority-plane"));
    for (name, _) in std::env::vars_os() {
        if name.to_string_lossy().starts_with("PERMGUARD_") {
            command.env_remove(name);
        }
    }
    command
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .and_then(|listener| listener.local_addr())
        .map(|address| address.port())
        .expect("a free port")
}

fn stop(mut child: Child) {
    let _ = child.kill();
    let _ = child.wait();
}

#[test]
fn help_names_the_product_and_exits_cleanly() {
    let output = binary().arg("--help").output().expect("the binary runs");
    assert!(output.status.success(), "{output:?}");
    let text = String::from_utf8_lossy(&output.stdout);
    assert!(text.contains("Permguard authority plane"), "{text}");
    assert!(text.contains("permguard-authority-plane"), "{text}");
}

#[test]
fn the_binary_serves_the_authority_plane_alone_and_issues_a_token() {
    let dir =
        std::env::temp_dir().join(format!("permguard-authority-binary-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("the scratch directory is created");
    let (port, host_port) = (free_port(), free_port());
    std::fs::write(
        dir.join("config.yml"),
        format!(
            "development_mode: true\nautogenerate: true\nassurance:\n  profile: development\n\
             log:\n  level: info\n  format: json\n\
             host:\n  addr: 127.0.0.1:{host_port}\n\
             runtime:\n  planes: [authority]\n\
             authority:\n  url: http://127.0.0.1:{port}\n\
             authorityPlane:\n  public:\n    http: {{ addr: 127.0.0.1:{port} }}\n"
        ),
    )
    .expect("the config writes");
    let mut child = binary()
        .arg(dir.join("config.yml"))
        .env("PERMGUARD_WORKING_DIR", &dir)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("the binary starts");
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
    let outcome = (|| {
        if !seen.contains("server.started") {
            return Err(format!("the binary did not start: {seen}"));
        }
        let text = std::fs::read_to_string(dir.join("planes/authority/admin.key"))
            .map_err(|error| format!("admin.key: {error}"))?;
        let field = |name: &str| {
            text.lines()
                .find_map(|line| line.strip_prefix(name).map(str::trim).map(str::to_owned))
                .ok_or(format!("no {name} in the key file"))
        };
        let (access_key, secret_key) = (field("access_key:")?, field("secret_key:")?);
        let issued = Command::new("curl")
            .args(["-sS", "--max-time", "10", "-w", "\n%{http_code}", "-u"])
            .arg(format!("{access_key}:{secret_key}"))
            .args(["--data", "grant_type=client_credentials"])
            .arg(format!("http://127.0.0.1:{port}/authority/v1/token"))
            .output()
            .expect("curl runs");
        let issued = String::from_utf8_lossy(&issued.stdout).into_owned();
        let discovery = Command::new("curl")
            .args(["-sS", "--max-time", "10"])
            .arg(format!(
                "http://127.0.0.1:{port}/.well-known/server-configuration"
            ))
            .output()
            .expect("curl runs");
        Ok::<_, String>((
            issued,
            String::from_utf8_lossy(&discovery.stdout).into_owned(),
        ))
    })();
    stop(child);
    let _ = std::fs::remove_dir_all(&dir);
    let (issued, discovery) = outcome.unwrap_or_else(|reason| panic!("{reason}"));
    assert!(issued.trim_end().ends_with("200"), "{issued}");
    assert!(issued.contains("\"token_type\":\"Bearer\""), "{issued}");
    assert!(
        discovery.contains("\"plane\":\"authority-plane\""),
        "{discovery}"
    );
    assert!(seen.contains("authority.admin_created"), "{seen}");
}
