// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! What a mirroring plane follows: which servers, and which of their zones
//! and ledgers.
//!
//! # Why the server is exact and the rest is a pattern
//!
//! A server URL is an identity: it is who you trust, whose certificate you
//! check, and whose key ring signs what you accept. A pattern there would
//! mean trusting something you cannot name in advance, so it is written out,
//! exactly, every time.
//!
//! Zones and ledgers are the opposite: they come and go while the deployment
//! runs, and a plane that had to be reconfigured for every new ledger would
//! be a plane that is always behind. So they are **patterns**, matched
//! against what the server actually lists — the plane asks "what do you
//! have", keeps what matches, and drops what no longer does.
//!
//! # Where the matching happens
//!
//! Not here. This crate carries what the file *declared* — the URL and the
//! patterns as written — because that is configuration; compiling a pattern
//! and deciding what it follows is behaviour, and it belongs to the plane
//! that mirrors. It is also why `permguard-core` still depends on four
//! crates and no more.
//!
//! # A structured record, not a flat key
//!
//! The server list comes from the configuration file only, for the same
//! reason realms do: there is no sensible way to state an array of servers
//! with their patterns in one environment variable, and a half-parsed list
//! is worse than no list. The *scalars* around it — the interval, the
//! timeout, how many mirrors run at once — ride the ordinary layered
//! pipeline, where the environment beats the file and the file beats the
//! default.
//!
//! # Where it is declared in the file
//!
//! Inside `dataPlane:`, because mirroring is a data plane's own business: it
//! is the plane that serves decisions that needs the policies, and a control
//! plane has nothing to mirror. A process that hosts both planes — the
//! all-in-one — therefore states it in the same place, under its `dataPlane`
//! section, and the top level stays what it has always been: the settings
//! both planes share.

use anyhow::{Result, bail};
use serde::Deserialize;

use crate::config::{
    SETTING_MIRRORS_ENABLED, SETTING_MIRRORS_EXPIRE_AFTER, SETTING_MIRRORS_INTERVAL,
    SETTING_MIRRORS_JITTER, SETTING_MIRRORS_PARALLELISM, SETTING_MIRRORS_STALE_AFTER,
    SETTING_MIRRORS_TIMEOUT,
};

/// One server to follow, as the configuration file declares it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MirrorSource {
    /// The exact base URL — `https://host[:port]`, or `grpcs://…`. Never a
    /// pattern: this is an identity, not a search.
    pub url: String,
    /// The trust material for reaching it: the authority its certificate is
    /// checked against, and — where the server asks for one — a certificate of
    /// our own. Absent means the platform trust store, which is what a public
    /// certificate needs and a private authority does not.
    pub tls: MirrorTls,
    /// The zone-name patterns to follow. Absent means every zone.
    pub zones: Vec<String>,
    /// The ledger-name patterns to follow inside a matching zone. Absent
    /// means every ledger of that zone.
    pub ledgers: Vec<String>,
}

/// A mirroring plane's synchronization loop, as the `dataPlane.sync` block of
/// the configuration file declares it.
///
/// The scalars come back as setting pairs, so they travel the same layered
/// pipeline as everything else and an environment variable still wins. The
/// servers come back as [`MirrorSource`], because a list cannot.
#[derive(Debug, Default, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MirrorsSection {
    #[serde(default)]
    enabled: Option<String>,
    #[serde(default)]
    interval: Option<String>,
    #[serde(default)]
    timeout: Option<String>,
    #[serde(default)]
    parallelism: Option<String>,
    #[serde(default)]
    jitter: Option<String>,
    /// How old the last verified synchronization may grow before this plane
    /// alarms. Absent or `0s`: no bound.
    #[serde(default)]
    stale_after: Option<String>,
    /// How old it may grow before this plane refuses to answer from the
    /// mirror (`503`). Absent or `0s`: no bound.
    #[serde(default)]
    expire_after: Option<String>,
    /// The servers to follow. A list, not a flat setting: an array of servers
    /// with their patterns has no sensible single-variable form, and a
    /// half-parsed list is worse than none.
    #[serde(default)]
    servers: Vec<MirrorServerSection>,
}

/// One server this plane follows: an exact URL, and the patterns of what to
/// take from it.
#[derive(Debug, Default, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct MirrorServerSection {
    /// The exact base URL — never a pattern: this is who you trust.
    url: String,
    /// How this server is trusted, and who we say we are to it.
    #[serde(default)]
    tls: MirrorTls,
    /// Zone-name patterns. Absent means every zone the server lists.
    #[serde(default)]
    zones: Vec<String>,
    /// Ledger-name patterns inside a matching zone. Absent means every one.
    #[serde(default)]
    ledgers: Vec<String>,
}

impl MirrorsSection {
    /// The scalars, as pairs for the configuration-file layer.
    pub fn settings(&self) -> Vec<(String, String)> {
        [
            (SETTING_MIRRORS_ENABLED, self.enabled.as_ref()),
            (SETTING_MIRRORS_INTERVAL, self.interval.as_ref()),
            (SETTING_MIRRORS_TIMEOUT, self.timeout.as_ref()),
            (SETTING_MIRRORS_PARALLELISM, self.parallelism.as_ref()),
            (SETTING_MIRRORS_JITTER, self.jitter.as_ref()),
            (SETTING_MIRRORS_STALE_AFTER, self.stale_after.as_ref()),
            (SETTING_MIRRORS_EXPIRE_AFTER, self.expire_after.as_ref()),
        ]
        .into_iter()
        .filter_map(|(key, value)| value.map(|value| (key.to_owned(), value.clone())))
        .collect()
    }

    /// The servers this plane follows, as declared.
    pub fn sources(&self) -> Vec<MirrorSource> {
        self.servers
            .iter()
            .map(|server| MirrorSource {
                url: server.url.clone(),
                tls: server.tls.clone(),
                zones: server.zones.clone(),
                ledgers: server.ledgers.clone(),
            })
            .collect()
    }
}

/// The trust material for one server, as declared. Paths resolve against the
/// working directory, like every other path in the file.
///
/// There is deliberately no "skip verification" here. A plane that accepts any
/// certificate is a plane whose policies come from whoever answers the port,
/// and unlike a CLI run by a human who reads the warning, nobody is watching
/// this one.
#[derive(Debug, Default, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MirrorTls {
    /// The authority the server's certificate is checked against.
    #[serde(default)]
    pub ca_file: Option<String>,
    /// Our own certificate, for a server that asks for one — mutual TLS.
    #[serde(default)]
    pub cert: Option<String>,
    /// The key belonging to that certificate.
    #[serde(default)]
    pub key: Option<String>,
    /// The name to check the certificate against, when the server is reached
    /// by an address its certificate does not name.
    #[serde(default)]
    pub server_name: Option<String>,
}

/// Checks one declared source for shape, at startup, where somebody is
/// watching: a URL that is not a URL is a configuration mistake, and a
/// deployment should hear about it before it starts serving decisions from a
/// server it never reached.
pub fn check_source(input: &MirrorSource) -> Result<()> {
    let url = input.url.trim().to_owned();
    if url.is_empty() {
        bail!("a sync source needs a server URL");
    }
    let Some((scheme, rest)) = url.split_once("://") else {
        bail!("the sync source `{url}` is not a URL: write https://host[:port]");
    };
    if !matches!(scheme, "http" | "https" | "grpc" | "grpcs") {
        bail!(
            "the sync source `{url}` names the scheme `{scheme}`: use http, https, grpc or grpcs"
        );
    }
    if rest.is_empty() {
        bail!("the sync source `{url}` names no host");
    }
    // Half a client identity is no client identity: a certificate with no key
    // cannot be presented, and a key with no certificate has nothing to prove.
    match (&input.tls.cert, &input.tls.key) {
        (Some(_), None) => bail!("the sync source `{url}` names a certificate but no key"),
        (None, Some(_)) => bail!("the sync source `{url}` names a key but no certificate"),
        _ => {}
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;

    fn declared(url: &str) -> MirrorSource {
        MirrorSource {
            url: url.to_owned(),
            tls: MirrorTls::default(),
            zones: Vec::new(),
            ledgers: Vec::new(),
        }
    }

    #[test]
    fn a_well_shaped_source_passes() {
        for url in [
            "https://control.acme.com",
            "http://127.0.0.1:6443",
            "grpcs://control.internal:6443",
        ] {
            check_source(&declared(url)).expect(url);
        }
    }

    #[test]
    fn half_a_client_identity_is_refused() {
        let mut half = declared("https://control.acme.com");
        half.tls.cert = Some("tls/client.pem".to_owned());
        let error = check_source(&half).expect_err("a certificate needs its key");
        assert!(error.to_string().contains("no key"), "{error}");

        let mut other = declared("https://control.acme.com");
        other.tls.key = Some("tls/client.key".to_owned());
        let error = check_source(&other).expect_err("a key needs its certificate");
        assert!(error.to_string().contains("no certificate"), "{error}");
    }

    #[test]
    fn the_file_shape_carries_the_trust_material_and_the_scalars_stay_settings() {
        let section: MirrorsSection = serde_norway::from_str(
            "enabled: \"true\"\ninterval: \"15s\"\nservers:\n  - url: \"grpcs://control:6443\"\n    tls:\n      ca_file: tls/ca.pem\n      cert: tls/client.pem\n      key: tls/client.key\n    zones: [\"acme\"]\n",
        )
        .expect("the section parses");

        assert_eq!(
            section.settings(),
            vec![
                (SETTING_MIRRORS_ENABLED.to_owned(), "true".to_owned()),
                (SETTING_MIRRORS_INTERVAL.to_owned(), "15s".to_owned()),
            ]
        );
        let sources = section.sources();
        assert_eq!(sources.len(), 1);
        assert_eq!(sources[0].url, "grpcs://control:6443");
        assert_eq!(sources[0].zones, vec!["acme".to_owned()]);
        assert_eq!(sources[0].tls.ca_file.as_deref(), Some("tls/ca.pem"));
        check_source(&sources[0]).expect("a fully-dressed source is well shaped");
    }

    #[test]
    fn a_server_is_named_exactly_and_a_bad_one_is_refused_at_startup() {
        for (url, expected) in [
            ("", "needs a server URL"),
            ("control.acme.com", "is not a URL"),
            ("ftp://control.acme.com", "names the scheme"),
            ("https://", "names no host"),
        ] {
            let error = check_source(&declared(url)).expect_err(url).to_string();
            assert!(error.contains(expected), "for `{url}`: {error}");
        }
    }
}
