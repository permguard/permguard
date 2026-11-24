// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! What the tests of a store kept on the object store share: the test bucket, and a prefix of a
//! test's own in it.
//!
//! The tests need an S3 server. `PERMGUARD_TEST_S3` names it, as
//! `host=127.0.0.1 port=7070 bucket=permguard access=… secret=… region=us-east-1`, and
//! `PERMGUARD_TEST_S3_CA` the file of the authority its certificate is verified against;
//! without the second the connection is in the clear, which a loopback address allows.
//! `scripts/test-s3.sh` starts a disposable server and sets both. Without the first a test is
//! skipped, and says so.

#![allow(clippy::expect_used, clippy::panic)]

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use zeroize::Zeroizing;

use crate::{Bucket, Config, Tls};

const SERVER: &str = "PERMGUARD_TEST_S3";
const AUTHORITY: &str = "PERMGUARD_TEST_S3_CA";

static NEXT: AtomicU64 = AtomicU64::new(0);

/// The roots the test server's certificate is verified against, when the run names them.
pub fn roots() -> Option<Arc<rustls::RootCertStore>> {
    use rustls::pki_types::pem::PemObject as _;

    let pem = std::fs::read(std::env::var(AUTHORITY).ok()?).expect("the authority's file reads");
    let mut roots = rustls::RootCertStore::empty();
    for certificate in rustls::pki_types::CertificateDer::pem_slice_iter(&pem) {
        roots
            .add(certificate.expect("the authority's file holds certificates"))
            .expect("a certificate is a root");
    }
    Some(Arc::new(roots))
}

/// The test server's configuration with `prefix` and `tls`; `None`, with a line saying so,
/// when the run names no server.
pub fn config(test: &str, prefix: &str, tls: Tls) -> Option<Config> {
    let Ok(server) = std::env::var(SERVER) else {
        eprintln!("skipped {test}: {SERVER} names no S3 server");
        return None;
    };
    let field = |name: &str| {
        server
            .split_whitespace()
            .find_map(|pair| pair.strip_prefix(&format!("{name}=")))
            .unwrap_or_else(|| panic!("{SERVER} names no {name}"))
            .to_owned()
    };
    Some(Config {
        host: field("host"),
        port: field("port").parse().expect("a port"),
        tls,
        region: field("region"),
        bucket: field("bucket"),
        prefix: prefix.to_owned(),
        access_key: field("access"),
        secret: Zeroizing::new(field("secret")),
        session_token: None,
        encryption: None,
        timeout: Duration::from_secs(20),
    })
}

/// A client of the test bucket under a prefix no other test of the run has; `None` when the
/// run names no server.
pub fn scratch(test: &str) -> Option<Bucket> {
    let prefix = format!(
        "t{}-{}-{}/",
        std::process::id(),
        permguard_core::time::unix_now(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    );
    let tls = roots().map_or(Tls::Disabled, Tls::Verified);
    Some(Bucket::connect(config(test, &prefix, tls)?).expect("a client of the test bucket"))
}
