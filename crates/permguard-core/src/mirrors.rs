// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! What a mirroring plane follows, and how the file narrows it.
//!
//! # Sources a membership binds, never a URL
//!
//! A Data Plane mirrors the `policy.mirror` tasks of its Host's memberships: the coordinator, its
//! `control.attest` set and the scope are all bound by the signed manifest, so the file names no
//! server, no TLS root and no statement key (WP-7.2a). A process hosting both Planes, the
//! all-in-one, also mirrors its own Control Plane through a local task the Host adds, in-process
//! and under its own `control.attest` set (WP-7.7). The configured server list, a URL with its
//! TLS material and the ring taken at first contact, is retired: v0.1.6 was the last release that
//! followed one, and a file still naming `servers` is refused, saying what replaces it.
//!
//! # Narrowing
//!
//! Zones and ledgers come and go while the deployment runs, so the file narrows by anchored
//! patterns: `mirrors.tasks` per membership task, `mirrors.local` for the local task. Compiling a
//! pattern and deciding what it follows is behaviour, and it belongs to the plane that mirrors.
//!
//! # Where it is declared in the file
//!
//! Inside `dataPlane:`, because mirroring is a data plane's own business. The *scalars* — the
//! interval, the timeout, how many mirrors run at once — ride the ordinary layered pipeline, where
//! the environment beats the file and the file beats the default; the lists come from the file.

use anyhow::{Result, bail};
use serde::Deserialize;

use crate::config::{
    SETTING_MIRRORS_ENABLED, SETTING_MIRRORS_EXPIRE_AFTER, SETTING_MIRRORS_INTERVAL,
    SETTING_MIRRORS_JITTER, SETTING_MIRRORS_PARALLELISM, SETTING_MIRRORS_REAP_GRACE,
    SETTING_MIRRORS_REVOCATION_OBJECTIVE, SETTING_MIRRORS_STALE_AFTER, SETTING_MIRRORS_TIMEOUT,
};

/// A mirroring plane's synchronization loop, as the `dataPlane.sync` block of
/// the configuration file declares it.
///
/// The scalars come back as setting pairs, so they travel the same layered
/// pipeline as everything else and an environment variable still wins. The
/// lists come back as structures, because a list cannot.
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
    /// How long a membership mirror no longer listed is kept before it is reaped (WP-7.2d).
    #[serde(default)]
    reap_grace: Option<String>,
    /// The revocation propagation objective this deployment declares (WP-7.2d).
    #[serde(default)]
    revocation_objective: Option<String>,
    /// The retired server list (WP-7.7): read only so a file still naming it is refused with what
    /// replaces it, rather than with an unknown field.
    #[serde(default)]
    servers: Option<Retired>,
    /// How the local task of a process hosting both Planes is narrowed (WP-7.7). Absent, it
    /// follows every zone and ledger of its own Control Plane.
    #[serde(default)]
    local: Option<MirrorLocalSection>,
    /// The `policy.mirror` tasks this plane narrows (WP-7.2a). Absent, every task of this Host's
    /// memberships is followed whole: the coordinator's signed selector already scopes it.
    #[serde(default)]
    tasks: Vec<MirrorTaskSection>,
    /// The aliases this plane assigns (WP-7.2d, F-17): a pair of names two coordinators both
    /// answer to is refused until one of these says which authority it means.
    #[serde(default)]
    aliases: Vec<MirrorAliasSection>,
}

/// One alias, as the file assigns it.
#[derive(Debug, Default, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct MirrorAliasSection {
    /// The zone a request names, by name or id.
    zone: String,
    /// The ledger a request names, by name or id.
    ledger: String,
    /// The coordinator Host whose ledger it resolves to, as `host peers list` shows its id.
    authority: String,
}

/// An alias (WP-7.2d, F-17): the pair of names a request uses, resolved to the ledger one
/// authority serves under them, and to nothing else.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MirrorAlias {
    pub zone: String,
    pub ledger: String,
    /// The coordinator Host, a lowercase dashed UUID.
    pub authority: String,
}

/// One `policy.mirror` task, as the file narrows it: by its membership and task ids, with
/// anchored zone and ledger patterns. No URL, TLS material or statement key: the membership binds
/// those.
#[derive(Debug, Default, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct MirrorTaskSection {
    /// The membership id, as `host members list` shows it.
    membership: String,
    /// The task id inside that membership's manifest.
    task: String,
    /// Zone-name patterns. Absent means every zone the task lists.
    #[serde(default)]
    zones: Vec<String>,
    /// Ledger-name patterns inside a matching zone. Absent means every one.
    #[serde(default)]
    ledgers: Vec<String>,
}

/// One `policy.mirror` task this plane follows narrowed (WP-7.2a).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MirrorTaskSelection {
    /// The membership id, lowercase, as `host members list` shows it.
    pub membership: String,
    pub task: String,
    pub zones: Vec<String>,
    pub ledgers: Vec<String>,
}

/// A retired key: whatever it held is read and dropped, so its presence can be refused by name.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
struct Retired;

impl<'de> Deserialize<'de> for Retired {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        serde::de::IgnoredAny::deserialize(deserializer)?;
        Ok(Self)
    }
}

/// The local task's narrowing, as the file declares it.
#[derive(Debug, Default, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct MirrorLocalSection {
    /// Zone-name patterns. Absent means every zone.
    #[serde(default)]
    zones: Vec<String>,
    /// Ledger-name patterns inside a matching zone. Absent means every one.
    #[serde(default)]
    ledgers: Vec<String>,
}

/// How the local task of a process hosting both Planes is narrowed (WP-7.7): anchored zone and
/// ledger patterns, empty meaning every one.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MirrorLocal {
    pub zones: Vec<String>,
    pub ledgers: Vec<String>,
}

/// Why a file naming `dataPlane.mirrors.servers` is refused (WP-7.7).
pub const SERVERS_RETIRED: &str = "`dataPlane.mirrors.servers` is retired: a Data Plane no longer \
     mirrors a configured URL (v0.1.6 was the last release that did). A Data Plane in its own \
     process mirrors the `policy.mirror` tasks of its Host's memberships: enroll it with \
     `permguard host members join`, and narrow them with `mirrors.tasks`. A process hosting both \
     Planes mirrors its own Control Plane in-process: remove `servers`, and narrow it with \
     `mirrors.local`.";

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
            (SETTING_MIRRORS_REAP_GRACE, self.reap_grace.as_ref()),
            (
                SETTING_MIRRORS_REVOCATION_OBJECTIVE,
                self.revocation_objective.as_ref(),
            ),
        ]
        .into_iter()
        .filter_map(|(key, value)| value.map(|value| (key.to_owned(), value.clone())))
        .collect()
    }

    /// The `policy.mirror` tasks this plane narrows, as declared (WP-7.2a).
    pub fn task_selections(&self) -> Vec<MirrorTaskSelection> {
        self.tasks
            .iter()
            .map(|task| MirrorTaskSelection {
                membership: task.membership.trim().to_ascii_lowercase(),
                task: task.task.trim().to_owned(),
                zones: task.zones.clone(),
                ledgers: task.ledgers.clone(),
            })
            .collect()
    }

    /// The aliases this plane assigns, as declared (WP-7.2d).
    pub fn aliases(&self) -> Vec<MirrorAlias> {
        self.aliases
            .iter()
            .map(|alias| MirrorAlias {
                zone: alias.zone.trim().to_owned(),
                ledger: alias.ledger.trim().to_owned(),
                authority: alias.authority.trim().to_ascii_lowercase(),
            })
            .collect()
    }

    /// Whether the file still names the retired server list (WP-7.7).
    pub fn names_servers(&self) -> bool {
        self.servers.is_some()
    }

    /// The local task's narrowing, as declared (WP-7.7).
    pub fn local(&self) -> Option<MirrorLocal> {
        self.local.as_ref().map(|local| MirrorLocal {
            zones: local.zones.clone(),
            ledgers: local.ledgers.clone(),
        })
    }
}

/// The trust material for reaching one server, as declared: what a decision log destination
/// still names (WP-6.5 removes it with the single configured destination). Paths resolve against
/// the working directory, like every other path in the file.
///
/// There is deliberately no "skip verification" here: nobody is watching a server process read
/// the warning.
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

/// Checks a configured server for shape, at startup, where somebody is watching: what a decision
/// log or event store destination names (WP-6.5 retires them). A URL that is not a URL is a
/// configuration mistake, and half a client identity is no client identity.
pub fn check_server(url: &str, tls: &MirrorTls) -> Result<()> {
    let url = url.trim();
    if url.is_empty() {
        bail!("a server needs its URL");
    }
    let Some((scheme, rest)) = url.split_once("://") else {
        bail!("the server `{url}` is not a URL: write https://host[:port]");
    };
    if !matches!(scheme, "http" | "https" | "grpc" | "grpcs") {
        bail!("the server `{url}` names the scheme `{scheme}`: use http, https, grpc or grpcs");
    }
    if rest.is_empty() {
        bail!("the server `{url}` names no host");
    }
    match (&tls.cert, &tls.key) {
        (Some(_), None) => bail!("the server `{url}` names a certificate but no key"),
        (None, Some(_)) => bail!("the server `{url}` names a key but no certificate"),
        _ => {}
    }

    Ok(())
}

/// Checks one alias for shape, at startup: both names, and the authority as a dashed UUID.
pub fn check_alias(alias: &MirrorAlias) -> Result<()> {
    if alias.zone.is_empty() || alias.ledger.is_empty() {
        bail!("an alias names its zone and its ledger");
    }
    let dashed = alias.authority.len() == 36
        && alias.authority.char_indices().all(|(at, held)| match at {
            8 | 13 | 18 | 23 => held == '-',
            _ => held.is_ascii_hexdigit() && !held.is_ascii_uppercase(),
        });
    if !dashed {
        bail!(
            "the alias `{}/{}` names the authority `{}`: write the coordinator Host's id as a \
             dashed UUID",
            alias.zone,
            alias.ledger,
            alias.authority
        );
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;

    /// WP-7.2d: the scalars travel as settings, the aliases as a structure, each checked.
    #[test]
    fn the_reap_grace_the_objective_and_the_aliases_are_read() {
        let section: MirrorsSection = serde_norway::from_str(
            "reap_grace: \"10m\"\nrevocation_objective: \"2m\"\naliases:\n  - zone: acme\n    ledger: main\n    authority: \" 0A1B2C3D-0000-4000-8000-00000000000F \"\n",
        )
        .expect("the section parses");
        assert_eq!(
            section.settings(),
            vec![
                (SETTING_MIRRORS_REAP_GRACE.to_owned(), "10m".to_owned()),
                (
                    SETTING_MIRRORS_REVOCATION_OBJECTIVE.to_owned(),
                    "2m".to_owned()
                ),
            ]
        );
        let aliases = section.aliases();
        assert_eq!(
            aliases,
            vec![MirrorAlias {
                zone: "acme".into(),
                ledger: "main".into(),
                authority: "0a1b2c3d-0000-4000-8000-00000000000f".into(),
            }]
        );
        check_alias(&aliases[0]).expect("well shaped");
        for (zone, ledger, authority, expected) in [
            (
                "",
                "main",
                "0a1b2c3d-0000-4000-8000-00000000000f",
                "names its zone",
            ),
            (
                "acme",
                "",
                "0a1b2c3d-0000-4000-8000-00000000000f",
                "names its zone",
            ),
            (
                "acme",
                "main",
                "0a1b2c3d00004000800000000000000f",
                "dashed UUID",
            ),
            (
                "acme",
                "main",
                "0A1B2C3D-0000-4000-8000-00000000000F",
                "dashed UUID",
            ),
            (
                "acme",
                "main",
                "0a1b2c3d-0000-4000-8000-00000000000g",
                "dashed UUID",
            ),
        ] {
            let error = check_alias(&MirrorAlias {
                zone: zone.into(),
                ledger: ledger.into(),
                authority: authority.into(),
            })
            .expect_err(authority);
            assert!(error.to_string().contains(expected), "{error}");
        }
        assert!(
            serde_norway::from_str::<MirrorsSection>(
                "aliases:\n  - zone: acme\n    ledger: main\n    authority: x\n    url: y\n"
            )
            .is_err(),
            "an alias is closed"
        );
    }

    /// WP-7.7: the retired server list is refused by name; the local task is narrowed by
    /// patterns, and both lists stay closed.
    #[test]
    fn the_server_list_is_retired_and_the_local_task_is_narrowed() {
        let section: MirrorsSection = serde_norway::from_str(
            "enabled: \"true\"\ninterval: \"15s\"\nservers:\n  - url: \"grpcs://control:6443\"\n    tls:\n      ca_file: tls/ca.pem\n",
        )
        .expect("the section parses, so the refusal can say why");
        assert!(section.names_servers());
        assert_eq!(
            section.settings(),
            vec![
                (SETTING_MIRRORS_ENABLED.to_owned(), "true".to_owned()),
                (SETTING_MIRRORS_INTERVAL.to_owned(), "15s".to_owned()),
            ]
        );
        assert!(
            SERVERS_RETIRED.contains("members join") && SERVERS_RETIRED.contains("mirrors.local")
        );

        let section: MirrorsSection = serde_norway::from_str(
            "local:\n  zones: [\"acme\"]\n  ledgers: [\"main\", \"gov.*\"]\n",
        )
        .expect("the section parses");
        assert!(!section.names_servers());
        assert_eq!(
            section.local(),
            Some(MirrorLocal {
                zones: vec!["acme".to_owned()],
                ledgers: vec!["main".to_owned(), "gov.*".to_owned()],
            })
        );
        assert_eq!(
            serde_norway::from_str::<MirrorsSection>("enabled: \"true\"\n")
                .expect("parses")
                .local(),
            None
        );
        assert!(
            serde_norway::from_str::<MirrorsSection>("local:\n  url: x\n").is_err(),
            "the local narrowing is closed"
        );
    }

    #[test]
    fn a_configured_server_is_checked_for_shape() {
        for url in [
            "https://control.acme.com",
            "http://127.0.0.1:6443",
            "grpcs://control.internal:6443",
        ] {
            check_server(url, &MirrorTls::default()).expect(url);
        }
        for (url, expected) in [
            ("", "needs its URL"),
            ("control.acme.com", "is not a URL"),
            ("ftp://control.acme.com", "names the scheme"),
            ("https://", "names no host"),
        ] {
            let error = check_server(url, &MirrorTls::default())
                .expect_err(url)
                .to_string();
            assert!(error.contains(expected), "for `{url}`: {error}");
        }
        let half = MirrorTls {
            cert: Some("tls/client.pem".to_owned()),
            ..MirrorTls::default()
        };
        let error = check_server("https://control.acme.com", &half).expect_err("no key");
        assert!(error.to_string().contains("no key"), "{error}");
        let other = MirrorTls {
            key: Some("tls/client.key".to_owned()),
            ..MirrorTls::default()
        };
        let error = check_server("https://control.acme.com", &other).expect_err("no certificate");
        assert!(error.to_string().contains("no certificate"), "{error}");
    }
}
