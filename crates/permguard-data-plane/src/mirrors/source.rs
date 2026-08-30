// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! What this plane follows, with the patterns compiled.
//!
//! The declaration lives in the configuration ([`permguard_core::mirrors`]);
//! deciding whether a name matches is behaviour, and behaviour belongs to
//! the plane that mirrors. Patterns are **anchored**: `main` follows the
//! ledger `main` and not `main-staging`, because a configuration an operator
//! cannot predict is a configuration that eventually follows something
//! nobody asked for.

use std::path::Path;

use anyhow::{Context, Result};
use permguard_control_client::TlsOptions;
use permguard_core::mirrors::MirrorSource;

/// One server this plane follows, ready to answer questions about names.
#[derive(Debug, Clone)]
pub struct Source {
    url: String,
    tls: TlsOptions,
    zones: Patterns,
    ledgers: Patterns,
}

impl Source {
    /// Compiles one declared source. A broken pattern is refused here — at
    /// startup, loudly — rather than becoming a mirror that follows nothing.
    ///
    /// The trust material is resolved against `workdir` at the same time: a
    /// relative path in a configuration file means "next to the volume this
    /// process was given", exactly as it does for a listener's certificate.
    pub fn compile(input: &MirrorSource, workdir: &Path) -> Result<Self> {
        Ok(Self {
            url: input.url.trim().to_owned(),
            tls: TlsOptions {
                ca_file: input.tls.ca_file.as_ref().map(Into::into),
                cert_file: input.tls.cert.as_ref().map(Into::into),
                key_file: input.tls.key.as_ref().map(Into::into),
                server_name: input.tls.server_name.clone(),
                // Never: see `permguard_core::mirrors::MirrorTls`.
                skip_verify: false,
            }
            .rooted_at(workdir),
            zones: Patterns::compile(&input.zones, "zone")?,
            ledgers: Patterns::compile(&input.ledgers, "ledger")?,
        })
    }

    /// The server, exactly as configured.
    pub fn url(&self) -> &str {
        &self.url
    }

    /// How this server is trusted, and who we say we are to it.
    pub fn tls(&self) -> &TlsOptions {
        &self.tls
    }

    /// Whether this source follows a zone of this name.
    pub fn follows_zone(&self, name: &str) -> bool {
        self.zones.matches(name)
    }

    /// Whether it follows a ledger of this name.
    pub fn follows_ledger(&self, name: &str) -> bool {
        self.ledgers.matches(name)
    }

    /// What it was told to follow, for a log line that has to be readable.
    pub fn patterns(&self) -> (String, String) {
        (self.zones.describe(), self.ledgers.describe())
    }
}

/// A set of name patterns. Empty means everything — so an absent list and a
/// `.*` behave the same, and neither is a special case anywhere downstream.
#[derive(Debug, Clone, Default)]
struct Patterns {
    written: Vec<String>,
    compiled: Vec<regex::Regex>,
}

impl Patterns {
    fn compile(written: &[String], what: &str) -> Result<Self> {
        let compiled = written
            .iter()
            .map(|pattern| {
                regex::Regex::new(&format!("^(?:{pattern})$"))
                    .with_context(|| format!("reading the {what} pattern `{pattern}`"))
            })
            .collect::<Result<Vec<_>>>()?;

        Ok(Self {
            written: written.to_vec(),
            compiled,
        })
    }

    fn matches(&self, name: &str) -> bool {
        self.compiled.is_empty() || self.compiled.iter().any(|pattern| pattern.is_match(name))
    }

    fn describe(&self) -> String {
        if self.written.is_empty() {
            "*".to_owned()
        } else {
            self.written.join(",")
        }
    }
}

/// Compiles every declared source, or refuses the lot.
pub fn compile(inputs: &[MirrorSource], workdir: &Path) -> Result<Vec<Source>> {
    let sources: Vec<Source> = inputs
        .iter()
        .map(|input| Source::compile(input, workdir))
        .collect::<Result<_>>()?;
    check_overlap(&sources)?;

    Ok(sources)
}

/// Refuses a configuration that names one server twice.
///
/// A server URL is an identity: two entries for it would race each other for
/// the same mirrors, and whichever pattern set won would be decided by list
/// order. That is unambiguously a mistake, and it is the only thing decidable
/// here — whether two *different* servers own the same ledger cannot be known
/// until they are asked, so it is caught where the identities are actually
/// seen. See `round::contested`.
fn check_overlap(sources: &[Source]) -> Result<()> {
    for (index, source) in sources.iter().enumerate() {
        for other in sources.iter().skip(index + 1) {
            if source.url() == other.url() {
                anyhow::bail!(
                    "`{}` is configured twice: one server is one identity, and two entries for it \
                     would race each other for the same mirrors",
                    source.url()
                );
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;

    fn source(zones: &[&str], ledgers: &[&str]) -> Source {
        Source::compile(
            &MirrorSource {
                url: "https://control.acme.com".to_owned(),
                tls: permguard_core::mirrors::MirrorTls::default(),
                zones: zones.iter().map(|p| (*p).to_owned()).collect(),
                ledgers: ledgers.iter().map(|p| (*p).to_owned()).collect(),
            },
            Path::new("/var/lib/permguard"),
        )
        .expect("the source compiles")
    }

    #[test]
    fn a_relative_trust_path_resolves_against_the_volume() {
        let followed = Source::compile(
            &MirrorSource {
                url: "grpcs://control:6443".to_owned(),
                tls: permguard_core::mirrors::MirrorTls {
                    ca_file: Some("tls/ca.pem".to_owned()),
                    ..permguard_core::mirrors::MirrorTls::default()
                },
                zones: Vec::new(),
                ledgers: Vec::new(),
            },
            Path::new("/var/lib/permguard"),
        )
        .expect("the source compiles");

        assert_eq!(
            followed.tls().ca_file.as_deref(),
            Some(Path::new("/var/lib/permguard/tls/ca.pem"))
        );
        assert!(!followed.tls().skip_verify, "never offered, never on");
    }

    #[test]
    fn no_pattern_follows_everything() {
        let every = source(&[], &[]);

        assert!(every.follows_zone("acme"));
        assert!(every.follows_ledger("anything"));
        assert_eq!(every.patterns(), ("*".to_owned(), "*".to_owned()));
    }

    #[test]
    fn patterns_describe_whole_names() {
        let followed = source(&["acme-.*"], &["main"]);

        assert!(followed.follows_zone("acme-eu"));
        assert!(
            !followed.follows_zone("not-acme-eu"),
            "anchored at the start"
        );
        assert!(followed.follows_ledger("main"));
        assert!(
            !followed.follows_ledger("main-staging"),
            "anchored at the end: `main` is not a prefix"
        );
    }

    #[test]
    fn several_patterns_are_alternatives() {
        let followed = source(&["eu", "us"], &[]);

        assert!(followed.follows_zone("eu"));
        assert!(followed.follows_zone("us"));
        assert!(!followed.follows_zone("apac"));
    }

    #[test]
    fn a_broken_pattern_is_refused_where_somebody_is_watching() {
        let error = Source::compile(
            &MirrorSource {
                url: "https://control.acme.com".to_owned(),
                tls: permguard_core::mirrors::MirrorTls::default(),
                zones: vec!["acme-[".to_owned()],
                ledgers: Vec::new(),
            },
            Path::new("/var/lib/permguard"),
        )
        .expect_err("a broken pattern cannot compile")
        .to_string();

        assert!(error.contains("zone pattern `acme-[`"), "{error}");
    }
}

#[cfg(test)]
mod overlap {
    #![allow(clippy::expect_used)]

    use super::*;

    fn declared(url: &str, zones: &[&str]) -> MirrorSource {
        MirrorSource {
            url: url.to_owned(),
            tls: permguard_core::mirrors::MirrorTls::default(),
            zones: zones.iter().map(|pattern| (*pattern).to_owned()).collect(),
            ledgers: Vec::new(),
        }
    }

    #[test]
    fn two_servers_that_each_mirror_everything_are_a_legitimate_shape() {
        // Two control planes with disjoint zones, each followed by its URL
        // alone. Whether they really overlap is knowable only by asking them,
        // and that happens in the round.
        assert!(
            compile(
                &[
                    declared("https://eu.acme.com", &[]),
                    declared("https://us.acme.com", &[]),
                ],
                Path::new(".")
            )
            .is_ok()
        );
    }

    #[test]
    fn the_same_server_named_twice_is_refused_as_itself() {
        let said = compile(
            &[
                declared("https://one.acme.com", &["eu"]),
                declared("https://one.acme.com", &["us"]),
            ],
            Path::new("."),
        )
        .expect_err("this configuration is refused")
        .to_string();

        assert!(said.contains("configured twice"), "{said}");
    }
}
