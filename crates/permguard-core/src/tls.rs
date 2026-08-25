// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! What a build needs to know to serve over TLS, and to demand a certificate back.
//!
//! Types only: reading a file, parsing a certificate and building a server configuration all belong
//! to whoever implements a surface. What belongs here is the shape of the answer, so a surface and
//! the configuration that drives it agree on it without either depending on a TLS implementation.
//!
//! # Why the default is 1.3
//!
//! TLS 1.2 is not broken, but its long tail is: renegotiation, CBC constructions, static RSA key
//! exchange, and a cipher-suite negotiation with room to go wrong. 1.3 removed all of it. A product
//! whose whole subject is continuity of authority should not ship a default whose weakest allowed
//! configuration is a decade old — so 1.2 is available and has to be asked for by name.
//!
//! # Why revocation and reloading live on the material
//!
//! Both are properties of *this* material rather than of the process: which authority may revoke
//! these clients, and how often these files are re-read. Carrying them here means a listener needs no
//! extra arguments to honour them, and a build that assembles its own settings cannot forget to.

use std::fmt;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::Duration;

use anyhow::{Result, bail};

use crate::peer::AllowedPeer;

/// The lowest protocol version a listener will accept.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
pub enum TlsVersion {
    /// Accepted, and only when a deployment names it.
    V1_2,
    /// The default.
    #[default]
    V1_3,
}

impl TlsVersion {
    /// Returns the name this version is written as.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::V1_2 => "1.2",
            Self::V1_3 => "1.3",
        }
    }

    /// Every version a configuration may name.
    pub const ALL: [Self; 2] = [Self::V1_2, Self::V1_3];
}

impl FromStr for TlsVersion {
    type Err = anyhow::Error;

    fn from_str(value: &str) -> Result<Self> {
        match value.trim().trim_start_matches(['v', 'V']) {
            "1.2" | "1_2" | "12" => Ok(Self::V1_2),
            "1.3" | "1_3" | "13" => Ok(Self::V1_3),
            other => bail!(
                "`{other}` is not a TLS version: expected one of {}",
                Self::ALL.map(|version| version.as_str()).join(", ")
            ),
        }
    }
}

impl fmt::Display for TlsVersion {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Everything a listener needs to serve over TLS.
///
/// The presence of `client_ca` is what turns TLS into mTLS: with it, a client that presents no
/// certificate — or one no branch of that CA signed — never reaches the application at all. The
/// presence of `crl` is what makes that revocable before the certificate expires on its own.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsSettings {
    certificate: PathBuf,
    key: PathBuf,
    client_ca: Option<PathBuf>,
    crl: Option<PathBuf>,
    /// Who, of everybody the authority signed, this surface actually answers.
    ///
    /// This is the difference between authentication and authorisation, and it lives here because it
    /// travels with the rest of the posture: `client_ca` says which certificates are *genuine*, and
    /// an authority signs every client it was ever asked to — the SDK in another team's service, the
    /// batch job from last year. This list says which of them this surface is *for*. Empty means the
    /// handshake is the whole decision, which is the correct reading for a data plane that answers
    /// any workload the mesh signed — and the wrong one for anything administrative, which is why
    /// validation refuses an admin surface without it.
    allow: Vec<AllowedPeer>,
    min_version: TlsVersion,
    reload: Option<Duration>,
}

impl TlsSettings {
    /// Builds the settings for a listener that authenticates itself to its clients.
    pub fn new(certificate: impl Into<PathBuf>, key: impl Into<PathBuf>) -> Self {
        Self {
            certificate: certificate.into(),
            key: key.into(),
            client_ca: None,
            crl: None,
            allow: Vec::new(),
            min_version: TlsVersion::default(),
            reload: None,
        }
    }

    /// Demands a client certificate signed by the authority in `client_ca`.
    pub fn with_client_ca(mut self, client_ca: impl Into<PathBuf>) -> Self {
        self.client_ca = Some(client_ca.into());

        self
    }

    /// Refuses client certificates the authority has published as revoked.
    ///
    /// Without this, the only thing that ends a compromised client certificate's usefulness is its
    /// own expiry — which is exactly the window an attacker was hoping for.
    pub fn with_crl(mut self, crl: impl Into<PathBuf>) -> Self {
        self.crl = Some(crl.into());

        self
    }

    /// Answers only the peers this list names, of everybody the client authority signed.
    pub fn with_allow(mut self, allow: Vec<AllowedPeer>) -> Self {
        self.allow = allow;

        self
    }

    /// Returns who this surface answers, empty meaning everybody the handshake admits.
    pub fn allow(&self) -> &[AllowedPeer] {
        &self.allow
    }

    /// Lowers the accepted protocol floor from the default.
    pub fn with_min_version(mut self, min_version: TlsVersion) -> Self {
        self.min_version = min_version;

        self
    }

    /// Re-reads this material every `interval`, so a renewal does not need a restart.
    pub fn with_reload(mut self, interval: Duration) -> Self {
        self.reload = Some(interval);

        self
    }

    /// Stops re-reading this material.
    pub fn without_reload(mut self) -> Self {
        self.reload = None;

        self
    }

    /// Returns the certificate chain this listener presents.
    pub fn certificate(&self) -> &Path {
        &self.certificate
    }

    /// Returns the private key belonging to that chain.
    pub fn key(&self) -> &Path {
        &self.key
    }

    /// Returns the authority client certificates must be signed by, when this is mTLS.
    pub fn client_ca(&self) -> Option<&Path> {
        self.client_ca.as_deref()
    }

    /// Returns the revocation list client certificates are checked against, when there is one.
    pub fn crl(&self) -> Option<&Path> {
        self.crl.as_deref()
    }

    /// Returns the lowest protocol version accepted.
    pub fn min_version(&self) -> TlsVersion {
        self.min_version
    }

    /// Returns how often this material is re-read, when it is watched at all.
    pub fn reload(&self) -> Option<Duration> {
        self.reload
    }

    /// Returns every file this material is made of, which is what a watcher watches.
    pub fn files(&self) -> impl Iterator<Item = &Path> {
        [
            Some(self.certificate.as_path()),
            Some(self.key.as_path()),
            self.client_ca.as_deref(),
            self.crl.as_deref(),
        ]
        .into_iter()
        .flatten()
    }

    /// Reports whether a client certificate is demanded.
    pub fn is_mutual(&self) -> bool {
        self.client_ca.is_some()
    }

    /// Checks the settings name files that exist, before a listener tries to bind.
    ///
    /// A certificate discovered to be missing at the first connection is a certificate discovered by
    /// a user; discovering it at startup is the whole point of validating configuration.
    pub fn validate(&self) -> Result<()> {
        self.validate_in(Path::new("."))
    }

    /// Returns the same settings with every relative path resolved against `working_dir`.
    ///
    /// Configuration returns settings that have already been through this, so nothing downstream has
    /// to remember to do it — and a listener that opened `tls/server.pem` relative to whatever
    /// directory the process happened to start in would find it only by accident.
    pub fn resolved_in(&self, working_dir: &Path) -> Self {
        let resolve = |path: &Path| -> PathBuf {
            if path.is_absolute() {
                path.to_path_buf()
            } else {
                working_dir.join(path)
            }
        };

        Self {
            certificate: resolve(&self.certificate),
            key: resolve(&self.key),
            client_ca: self.client_ca.as_deref().map(resolve),
            crl: self.crl.as_deref().map(resolve),
            allow: self.allow.clone(),
            min_version: self.min_version,
            reload: self.reload,
        }
    }

    /// Checks the settings name files that exist, resolving relative paths against `working_dir`.
    pub fn validate_in(&self, working_dir: &Path) -> Result<()> {
        let resolve = |path: &Path| -> PathBuf {
            if path.is_absolute() {
                path.to_path_buf()
            } else {
                working_dir.join(path)
            }
        };

        // A revocation list with nothing to revoke against is a configuration that reads as stricter
        // than it is: the file is named, nobody is checked against it, and the deployment believes
        // otherwise. Refused rather than ignored.
        if self.crl.is_some() && self.client_ca.is_none() {
            bail!(
                "a revocation list is configured but no client authority is: there is nothing to \
                 check against it, so no client would ever be refused by it"
            );
        }

        for (what, path) in [
            ("certificate", Some(self.certificate.as_path())),
            ("private key", Some(self.key.as_path())),
            ("client CA", self.client_ca.as_deref()),
            ("revocation list", self.crl.as_deref()),
        ] {
            let Some(path) = path else {
                continue;
            };

            let resolved = resolve(path);

            if !resolved.is_file() {
                bail!(
                    "the TLS {what} {} is not a readable file",
                    resolved.display()
                );
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;

    #[test]
    fn test_the_default_floor_is_the_modern_one() {
        assert_eq!(TlsVersion::default(), TlsVersion::V1_3);
        assert_eq!(TlsSettings::new("c", "k").min_version(), TlsVersion::V1_3);
    }

    #[test]
    fn test_every_version_round_trips_through_its_name() {
        for version in TlsVersion::ALL {
            assert_eq!(
                version.as_str().parse::<TlsVersion>().expect("it parses"),
                version
            );
        }
    }

    #[test]
    fn test_the_spellings_a_configuration_file_is_likely_to_use_are_accepted() {
        for written in ["1.2", "v1.2", "1_2", "12"] {
            assert_eq!(
                written.parse::<TlsVersion>().expect("it parses"),
                TlsVersion::V1_2,
                "reading {written}"
            );
        }
    }

    #[test]
    fn test_an_unknown_version_lists_what_was_expected() {
        let error = "1.1".parse::<TlsVersion>().expect_err("1.1 is not offered");

        assert!(format!("{error}").contains("1.2, 1.3"));
    }

    #[test]
    fn test_a_client_authority_is_what_makes_it_mutual() {
        let plain = TlsSettings::new("c", "k");
        let mutual = TlsSettings::new("c", "k").with_client_ca("ca");

        assert!(!plain.is_mutual());
        assert!(mutual.is_mutual());
        assert_eq!(mutual.client_ca(), Some(Path::new("ca")));
    }

    #[test]
    fn test_settings_that_name_missing_files_are_refused_before_anything_binds() {
        let error = TlsSettings::new("/nonexistent/cert.pem", "/nonexistent/key.pem")
            .validate()
            .expect_err("the certificate is not there");

        assert!(format!("{error}").contains("/nonexistent/cert.pem"));
    }

    #[test]
    fn test_a_revocation_list_without_an_authority_is_refused_rather_than_ignored() {
        let error = TlsSettings::new("c", "k")
            .with_crl("crl.pem")
            .validate()
            .expect_err("there is nothing to revoke against");

        assert!(format!("{error}").contains("no client authority"));
    }

    #[test]
    fn test_every_file_the_material_is_made_of_is_offered_to_a_watcher() {
        let settings = TlsSettings::new("server.pem", "server.key")
            .with_client_ca("ca.pem")
            .with_crl("ca.crl");

        let watched: Vec<_> = settings.files().collect();

        assert_eq!(
            watched,
            [
                Path::new("server.pem"),
                Path::new("server.key"),
                Path::new("ca.pem"),
                Path::new("ca.crl")
            ]
        );
    }

    #[test]
    fn test_resolving_moves_every_path_into_the_volume_and_keeps_the_policy() {
        let resolved = TlsSettings::new("server.pem", "server.key")
            .with_client_ca("ca.pem")
            .with_crl("ca.crl")
            .with_reload(Duration::from_secs(30))
            .resolved_in(Path::new("/var/lib/permguard"));

        assert_eq!(
            resolved.certificate(),
            Path::new("/var/lib/permguard/server.pem")
        );
        assert_eq!(resolved.crl(), Some(Path::new("/var/lib/permguard/ca.crl")));
        assert_eq!(resolved.reload(), Some(Duration::from_secs(30)));
    }

    #[test]
    fn test_an_absolute_path_is_left_where_a_deployment_put_it() {
        let resolved = TlsSettings::new("/etc/permguard/server.pem", "server.key")
            .resolved_in(Path::new("/var/lib/permguard"));

        assert_eq!(
            resolved.certificate(),
            Path::new("/etc/permguard/server.pem")
        );
        assert_eq!(resolved.key(), Path::new("/var/lib/permguard/server.key"));
    }
}
