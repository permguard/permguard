// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! When the certificate a surface presents stops being valid, as a number somebody can alert on.
//!
//! # Why this is a test and not an assertion about a getter
//!
//! The failure it exists to prevent is an expired certificate on a Sunday. Everything needed to
//! prevent it — the reload, the renewal, the material loader — already worked before this number
//! existed; what was missing was anybody finding out *before* the handshake started failing.
//!
//! So the two claims worth establishing are that the number is right when the surface starts, and
//! that it **follows a renewal**. The second is the one that matters: a gauge describing whatever
//! certificate this process happened to boot with is a gauge that goes stale exactly when a renewal
//! silently stops working, which is the case it was added for.
//!
//! In its own binary because `reload_all` is process-wide: it acts on every surface alive in the
//! process, so any assertion about a reload is only meaningful when no other surface exists.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::Router;
use axum::routing::get;

use permguard_core::metrics::{Label, Metric, Recorder, Sample};
use permguard_core::{Metrics, TlsSettings};
use permguard_transport::{CERTIFICATE_EXPIRY, Surface, reload_all};

/// 2030-01-01T00:00:00Z, as the certificate says it.
const TWENTY_THIRTY: f64 = 1_893_456_000.0;

/// 2035-01-01T00:00:00Z — what a renewal moves it to.
const TWENTY_THIRTY_FIVE: f64 = 2_051_222_400.0;

/// Keeps the last value recorded against each metric.
///
/// Written here rather than borrowed from `permguard-std` so this crate's tests do not acquire a
/// dependency on an implementation of the contract they are testing against.
#[derive(Debug, Default)]
struct Captured(Mutex<Vec<(&'static str, f64)>>);

impl Captured {
    /// Returns the most recent value recorded against `name`.
    fn latest(&self, name: &str) -> Option<f64> {
        let recorded = self.0.lock().expect("the capture is not poisoned");

        recorded
            .iter()
            .rev()
            .find(|(recorded, _)| *recorded == name)
            .map(|(_, value)| *value)
    }
}

impl Recorder for Captured {
    fn record(&self, metric: &Metric, _labels: &[Label<'_>], value: f64) {
        if let Ok(mut recorded) = self.0.lock() {
            recorded.push((metric.name(), value));
        }
    }

    fn snapshot(&self) -> Vec<Sample> {
        Vec::new()
    }
}

/// An authority that issues certificates whose validity this test chooses.
struct Authority {
    directory: PathBuf,
    key: rcgen::KeyPair,
    params: rcgen::CertificateParams,
}

impl Authority {
    fn new() -> Self {
        let directory = std::env::temp_dir().join("permguard-expiry");
        let _ = std::fs::remove_dir_all(&directory);
        std::fs::create_dir_all(&directory).expect("the fixture directory is created");

        let mut params =
            rcgen::CertificateParams::new(Vec::new()).expect("the authority parameters build");
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params.not_before = rcgen::date_time_ymd(2020, 1, 1);
        params.not_after = rcgen::date_time_ymd(2040, 1, 1);

        let key = rcgen::KeyPair::generate().expect("the authority key is generated");
        let _ = params
            .self_signed(&key)
            .expect("the authority signs itself");

        Self {
            directory,
            key,
            params,
        }
    }

    /// Writes a certificate for `localhost` expiring on the first of `year`, over the same paths.
    ///
    /// The same paths on purpose: writing over them is what certbot, cert-manager and every other
    /// renewal does, and it is the case the gauge has to follow.
    fn issue_into(&self, year: i32, certificate_path: &Path, key_path: &Path) {
        let mut params =
            rcgen::CertificateParams::new(vec!["localhost".to_owned()]).expect("parameters build");
        params.not_before = rcgen::date_time_ymd(2020, 1, 1);
        params.not_after = rcgen::date_time_ymd(year, 1, 1);

        let key = rcgen::KeyPair::generate().expect("the key is generated");
        let issuer = rcgen::Issuer::from_params(&self.params, &self.key);
        let certificate = params
            .signed_by(&key, &issuer)
            .expect("the authority signs it");

        std::fs::write(certificate_path, certificate.pem()).expect("the certificate is written");
        std::fs::write(key_path, key.serialize_pem()).expect("the key is written");
    }
}

fn router() -> Router {
    Router::new().route("/", get(|| async { "served\n" }))
}

#[tokio::test]
async fn test_the_expiry_is_published_and_follows_a_renewal() {
    let authority = Authority::new();
    let certificate = authority.directory.join("server.pem");
    let key = authority.directory.join("server.key");
    authority.issue_into(2030, &certificate, &key);

    let captured = Arc::new(Captured::default());
    let settings = TlsSettings::new(&certificate, &key);
    let surface = Surface::listener("test", "127.0.0.1:0", router())
        .tls(Some(&settings))
        .metrics(Metrics::new(Arc::clone(&captured) as Arc<dyn Recorder>))
        .start()
        .await
        .expect("the listener binds");

    // 1. Published before anything is served, and it is the date in the certificate rather than an
    //    approximation of it.
    assert_eq!(
        captured.latest(CERTIFICATE_EXPIRY.name()),
        Some(TWENTY_THIRTY),
        "the expiry was not published, or is not the one the certificate asserts"
    );

    // 2. The renewal: a new certificate over the same paths, valid five years longer.
    authority.issue_into(2035, &certificate, &key);
    let reloaded = reload_all();
    assert_eq!(reloaded.reloaded, 1, "the live surface was not re-read");

    // 3. The number moved with it. Without this, a renewal that silently stopped running would leave
    //    a gauge reporting a comfortable date right up to the handshake that failed.
    assert_eq!(
        captured.latest(CERTIFICATE_EXPIRY.name()),
        Some(TWENTY_THIRTY_FIVE),
        "the expiry did not follow the renewal"
    );

    surface
        .stop(Duration::from_secs(5))
        .await
        .expect("the listener stops");
}

#[tokio::test]
async fn test_a_surface_in_the_clear_publishes_no_expiry() {
    // There is no certificate to have an opinion about. A zero here would read as "expired in 1970"
    // and page somebody about a surface that is working exactly as configured.
    let captured = Arc::new(Captured::default());
    let surface = Surface::listener("plain", "127.0.0.1:0", router())
        .metrics(Metrics::new(Arc::clone(&captured) as Arc<dyn Recorder>))
        .start()
        .await
        .expect("the listener binds");

    assert_eq!(captured.latest(CERTIFICATE_EXPIRY.name()), None);

    surface
        .stop(Duration::from_secs(5))
        .await
        .expect("the listener stops");
}
