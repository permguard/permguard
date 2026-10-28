// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The qualification registry: whether the volume's storage class, driver, filesystem and version
//! are qualified for the assurance profile in force (WP-1.3, H-04).
//!
//! | Profile       | Qualified tuple | Unknown tuple, or a compatibility platform                          |
//! | ------------- | --------------- | ------------------------------------------------------------------- |
//! | `development` | qualified       | accepted, reported; `compatibility_mode` when published or Windows  |
//! | `production`  | qualified       | refused                                                             |
//! | `regulated`   | qualified       | refused                                                             |
//!
//! The filesystem and version are what the probe observed; the storage class and driver come from
//! configuration, which never overrides what the probe observed, so the tuple is built here and
//! never taken from a caller. A tuple matches a qualified entry when its storage class, driver and
//! filesystem are equal and the entry's version is the running release or a prefix of it ending
//! before a `.` or a `-`: `6.8` covers `6.8.0-45-generic`, `6.8.0-45-generic` covers only itself. A
//! platform that meets the storage contract only as a compatibility mode (Windows) is never
//! qualified, whatever the registry says.
//!
//! A qualified record also proves encryption at rest (TS-5): from `production` a matching entry
//! must name its encryption mechanism, its evidence revision and when the evidence expires, and an
//! entry past its expiry is stale. An incomplete or stale entry is refused from `production`;
//! under `development` the volume runs unqualified, reported. A configuration boolean never proves
//! encryption: `storage.compatibility_mode` relaxes nothing from `production` (TS-5, deciding the
//! question WP-05 left open: the storage document keeps a missing, unknown or stale qualification
//! out of Ready, and a profile never disables its own controls). Below `production` it is the
//! published name of running on an unqualified platform.

use permguard_core::assurance::AssuranceProfile;
use permguard_core::volume::{Tuple, VolumeConfig};

use super::probe::{Identity, Reason, Unsupported};
use super::{PlatformMode, platform_mode};

/// Where the volume stands.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Standing {
    /// A qualified tuple, where its evidence is recorded, and when that evidence expires.
    Qualified {
        evidence: String,
        expires_at: Option<i64>,
    },
    /// Not qualified, accepted under the compatibility mode, which is published.
    CompatibilityMode,
    /// Not qualified, accepted because the profile is below `production`; reported.
    Unqualified,
}

/// The volume's tuple: what the probe observed, and what the operator declared.
pub fn running_tuple(identity: &Identity, config: &VolumeConfig) -> Tuple {
    Tuple {
        storage_class: config.storage_class.clone().unwrap_or_default(),
        driver: config.driver.clone().unwrap_or_default(),
        filesystem: identity.filesystem.clone(),
        version: identity.version.clone(),
    }
}

impl Standing {
    /// The word discovery and `host status` publish.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Qualified { .. } => "qualified",
            Self::CompatibilityMode => "compatibility_mode",
            Self::Unqualified => "unqualified",
        }
    }

    /// The evidence id of a qualified volume.
    pub fn evidence(&self) -> Option<&str> {
        match self {
            Self::Qualified { evidence, .. } => Some(evidence),
            _ => None,
        }
    }
}

/// Whether the volume the probe observed as `identity` may serve under `profile` at `now`, in
/// seconds since the epoch.
pub fn qualify(
    identity: &Identity,
    config: &VolumeConfig,
    profile: AssuranceProfile,
    now: i64,
) -> Result<Standing, Unsupported> {
    qualify_on(platform_mode(), identity, config, profile, now)
}

fn qualify_on(
    platform: PlatformMode,
    identity: &Identity,
    config: &VolumeConfig,
    profile: AssuranceProfile,
    now: i64,
) -> Result<Standing, Unsupported> {
    let running = running_tuple(identity, config);
    let compatibility_platform = platform == PlatformMode::Compatibility;
    let entry = config
        .qualified
        .iter()
        .filter(|_| !compatibility_platform)
        .filter(|entry| entry_is_whole(&entry.tuple))
        .find(|entry| matches(&entry.tuple, &running));
    if let Some(entry) = entry {
        return match not_proving(entry, now) {
            None => Ok(Standing::Qualified {
                evidence: entry.evidence.clone(),
                expires_at: entry.expires_at,
            }),
            Some(_) if profile == AssuranceProfile::Development => Ok(Standing::Unqualified),
            Some((reason, why)) => Err(Unsupported {
                reason,
                detail: format!(
                    "the qualified entry for storage class `{}`, driver `{}`, filesystem `{}`, \
                     version `{}` (evidence `{}`) {why}",
                    entry.tuple.storage_class,
                    entry.tuple.driver,
                    entry.tuple.filesystem,
                    entry.tuple.version,
                    entry.evidence
                ),
            }),
        };
    }
    let refused = |why: &str| Unsupported {
        reason: Reason::UnknownTuple,
        detail: format!(
            "storage class `{}`, driver `{}`, filesystem `{}`, version `{}` {why}",
            or_undeclared(&running.storage_class),
            or_undeclared(&running.driver),
            running.filesystem,
            running.version
        ),
    };
    match profile {
        AssuranceProfile::Development if compatibility_platform || config.compatibility_mode => {
            Ok(Standing::CompatibilityMode)
        }
        AssuranceProfile::Development => Ok(Standing::Unqualified),
        AssuranceProfile::Production if compatibility_platform => Err(refused(
            "runs on a platform that is only a compatibility mode, never qualified, and \
             `production` runs only on a qualified tuple",
        )),
        AssuranceProfile::Production => Err(refused(
            "is not qualified for `production`: list it in storage.qualified with its evidence, \
             encryption mechanism, revision and expiry; storage.compatibility_mode relaxes \
             nothing from `production`",
        )),
        AssuranceProfile::Regulated => Err(refused(
            "is not qualified, and `regulated` runs only on a qualified tuple",
        )),
    }
}

/// Why a matching entry does not prove encryption at rest at `now`: incomplete, or stale.
fn not_proving(
    entry: &permguard_core::volume::QualifiedTuple,
    now: i64,
) -> Option<(Reason, String)> {
    let missing: Vec<&str> = [
        ("encryption", entry.encryption.is_none()),
        ("revision", entry.revision.is_none()),
        ("expires_at", entry.expires_at.is_none()),
    ]
    .into_iter()
    .filter_map(|(key, absent)| absent.then_some(key))
    .collect();
    if !missing.is_empty() {
        return Some((
            Reason::QualificationIncomplete,
            format!(
                "does not name its {}: a record proves encryption at rest only with its \
                 mechanism, revision and expiry",
                missing.join(", ")
            ),
        ));
    }
    match entry.expires_at {
        Some(expires_at) if expires_at <= now => Some((
            Reason::QualificationStale,
            format!(
                "expired at {}: renew the evidence and its revision",
                permguard_core::time::to_rfc3339(expires_at)
            ),
        )),
        _ => None,
    }
}

/// Whether the qualified tuple `entry` covers the running tuple: the same storage class, driver and
/// filesystem, and a version that is the running release or a prefix of it ending at a `.` or `-`.
fn matches(entry: &Tuple, running: &Tuple) -> bool {
    let version = running.version == entry.version
        || running
            .version
            .strip_prefix(entry.version.as_str())
            .is_some_and(|rest| rest.starts_with(['.', '-']));
    entry.storage_class == running.storage_class
        && entry.driver == running.driver
        && entry.filesystem == running.filesystem
        && version
}

/// Whether a registry entry names all four parts: an empty part would match an undeclared one.
fn entry_is_whole(tuple: &Tuple) -> bool {
    [
        &tuple.storage_class,
        &tuple.driver,
        &tuple.filesystem,
        &tuple.version,
    ]
    .iter()
    .all(|part| !part.trim().is_empty())
}

fn or_undeclared(value: &str) -> &str {
    if value.is_empty() {
        "undeclared"
    } else {
        value
    }
}

#[cfg(test)]
mod tests {
    use permguard_core::volume::QualifiedTuple;

    use super::*;

    fn identity(filesystem: &str) -> Identity {
        Identity {
            filesystem: filesystem.to_owned(),
            version: "6.8.0".to_owned(),
            device: "66306".to_owned(),
        }
    }

    fn tuple(filesystem: &str) -> Tuple {
        Tuple {
            storage_class: "fast-ssd".to_owned(),
            driver: "ebs.csi.aws.com".to_owned(),
            filesystem: filesystem.to_owned(),
            version: "6.8.0".to_owned(),
        }
    }

    /// 2026-10-27T00:00:00Z.
    const NOW: i64 = 1_793_059_200;

    fn qualify_on(
        platform: PlatformMode,
        identity: &Identity,
        config: &VolumeConfig,
        profile: AssuranceProfile,
    ) -> Result<Standing, Unsupported> {
        super::qualify_on(platform, identity, config, profile, NOW)
    }

    fn config(compatibility_mode: bool) -> VolumeConfig {
        VolumeConfig {
            storage_class: Some("fast-ssd".to_owned()),
            driver: Some("ebs.csi.aws.com".to_owned()),
            qualified: vec![QualifiedTuple {
                tuple: tuple("ext4"),
                evidence: "QUAL-2026-01".to_owned(),
                encryption: Some("aws-kms".to_owned()),
                revision: Some("3".to_owned()),
                expires_at: Some(NOW + 86_400),
            }],
            compatibility_mode,
            ..VolumeConfig::default()
        }
    }

    const PROFILES: [AssuranceProfile; 3] = [
        AssuranceProfile::Development,
        AssuranceProfile::Production,
        AssuranceProfile::Regulated,
    ];

    #[test]
    fn the_tuple_takes_what_the_probe_observed_and_what_the_operator_declared() {
        assert_eq!(
            running_tuple(&identity("xfs"), &config(false)),
            tuple("xfs")
        );
        let undeclared = running_tuple(&identity("xfs"), &VolumeConfig::default());
        assert_eq!(
            (
                undeclared.storage_class.as_str(),
                undeclared.driver.as_str()
            ),
            ("", "")
        );
    }

    #[test]
    fn a_qualified_tuple_serves_under_every_profile() {
        for profile in PROFILES {
            assert_eq!(
                qualify_on(
                    PlatformMode::Full,
                    &identity("ext4"),
                    &config(false),
                    profile
                ),
                Ok(Standing::Qualified {
                    evidence: "QUAL-2026-01".to_owned(),
                    expires_at: Some(NOW + 86_400),
                })
            );
        }
    }

    #[test]
    fn an_unknown_tuple_is_reported_in_development_and_refused_from_production() {
        let unknown = identity("btrfs");
        let on = |compatibility, profile| {
            qualify_on(
                PlatformMode::Full,
                &unknown,
                &config(compatibility),
                profile,
            )
        };
        assert_eq!(
            on(false, AssuranceProfile::Development),
            Ok(Standing::Unqualified)
        );
        assert_eq!(
            on(false, AssuranceProfile::Production)
                .expect_err("refused")
                .reason,
            Reason::UnknownTuple
        );
        assert_eq!(
            on(true, AssuranceProfile::Development),
            Ok(Standing::CompatibilityMode),
            "published below `production`"
        );
        // TS-5: the compatibility mode relaxes nothing from `production`.
        for compatibility in [false, true] {
            assert_eq!(
                on(compatibility, AssuranceProfile::Production)
                    .expect_err("refused")
                    .reason,
                Reason::UnknownTuple
            );
            assert_eq!(
                on(compatibility, AssuranceProfile::Regulated)
                    .expect_err("regulated runs only qualified")
                    .reason,
                Reason::UnknownTuple
            );
        }
    }

    /// A qualified version covers the running release it names or prefixes at a `.` or `-`, and
    /// nothing else.
    #[test]
    fn a_qualified_version_covers_its_release_and_the_releases_it_prefixes() {
        let mut broad = config(false);
        broad.qualified[0].tuple.version = "6.8".to_owned();
        for release in ["6.8", "6.8.0-45-generic", "6.8.0-47-generic", "6.8-rc1"] {
            let mut running = identity("ext4");
            running.version = release.to_owned();
            assert!(
                qualify_on(
                    PlatformMode::Full,
                    &running,
                    &broad,
                    AssuranceProfile::Production
                )
                .is_ok(),
                "{release}"
            );
        }
        for release in ["6.80.1", "6.9.0", "6", "16.8.0"] {
            let mut running = identity("ext4");
            running.version = release.to_owned();
            assert!(
                qualify_on(
                    PlatformMode::Full,
                    &running,
                    &broad,
                    AssuranceProfile::Production
                )
                .is_err(),
                "{release}"
            );
        }
        let mut exact = config(false);
        exact.qualified[0].tuple.version = "6.8.0-45-generic".to_owned();
        let mut newer = identity("ext4");
        newer.version = "6.8.0-47-generic".to_owned();
        assert!(
            qualify_on(
                PlatformMode::Full,
                &newer,
                &exact,
                AssuranceProfile::Production
            )
            .is_err()
        );
    }

    /// A compatibility platform is never qualified, even by a matching entry.
    #[test]
    fn a_compatibility_platform_is_never_qualified() {
        let on = |compatibility, profile| {
            qualify_on(
                PlatformMode::Compatibility,
                &identity("ext4"),
                &config(compatibility),
                profile,
            )
        };
        assert_eq!(
            on(false, AssuranceProfile::Development),
            Ok(Standing::CompatibilityMode)
        );
        assert!(on(false, AssuranceProfile::Production).is_err());
        assert!(on(true, AssuranceProfile::Production).is_err());
        assert!(on(true, AssuranceProfile::Regulated).is_err());
    }

    /// An undeclared storage class or driver matches nothing, not even an entry with empty parts.
    #[test]
    fn an_undeclared_part_matches_no_qualified_tuple() {
        let mut declared = config(false);
        declared.driver = None;
        let refused = qualify_on(
            PlatformMode::Full,
            &identity("ext4"),
            &declared,
            AssuranceProfile::Production,
        )
        .expect_err("refused");
        assert!(refused.detail.contains("undeclared"), "{refused}");

        let mut hollow = config(false);
        hollow.driver = None;
        hollow.qualified[0].tuple.driver = String::new();
        assert!(
            qualify_on(
                PlatformMode::Full,
                &identity("ext4"),
                &hollow,
                AssuranceProfile::Production
            )
            .is_err()
        );
    }

    /// TS-5: from `production` a matching entry proves encryption at rest only with its
    /// mechanism, revision and expiry, and only until it expires; the compatibility mode does not
    /// cover an entry the operator named. `development` runs on it unqualified.
    #[test]
    fn an_incomplete_or_stale_record_is_refused_from_production() {
        let incomplete = |strip: fn(&mut QualifiedTuple)| {
            let mut config = config(true);
            strip(&mut config.qualified[0]);
            config
        };
        let cases: [(VolumeConfig, Reason, &str); 4] = [
            (
                incomplete(|e| e.encryption = None),
                Reason::QualificationIncomplete,
                "encryption",
            ),
            (
                incomplete(|e| e.revision = None),
                Reason::QualificationIncomplete,
                "revision",
            ),
            (
                incomplete(|e| e.expires_at = None),
                Reason::QualificationIncomplete,
                "expires_at",
            ),
            (
                incomplete(|e| e.expires_at = Some(NOW)),
                Reason::QualificationStale,
                "expired at",
            ),
        ];
        for (config, reason, said) in cases {
            for profile in [AssuranceProfile::Production, AssuranceProfile::Regulated] {
                let refused = qualify_on(PlatformMode::Full, &identity("ext4"), &config, profile)
                    .expect_err("refused");
                assert_eq!(refused.reason, reason);
                assert!(refused.detail.contains(said), "{refused}");
                assert!(refused.detail.contains("QUAL-2026-01"), "{refused}");
            }
            assert_eq!(
                qualify_on(
                    PlatformMode::Full,
                    &identity("ext4"),
                    &config,
                    AssuranceProfile::Development
                ),
                Ok(Standing::Unqualified)
            );
        }
        let fresh = config(false);
        let standing = super::qualify_on(
            PlatformMode::Full,
            &identity("ext4"),
            &fresh,
            AssuranceProfile::Regulated,
            NOW + 86_399,
        )
        .expect("still valid a second before it expires");
        assert_eq!(
            (standing.as_str(), standing.evidence()),
            ("qualified", Some("QUAL-2026-01"))
        );
    }
}
