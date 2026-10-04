// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The qualification registry: whether the volume's storage class, driver, filesystem and version
//! are qualified for the assurance profile in force (WP-1.3, H-04).
//!
//! | Profile       | Qualified tuple | Unknown tuple, or a compatibility platform                     |
//! | ------------- | --------------- | -------------------------------------------------------------- |
//! | `development` | qualified       | accepted, reported                                             |
//! | `production`  | qualified       | refused, unless `storage.compatibility_mode` is on (published) |
//! | `regulated`   | qualified       | refused                                                        |
//!
//! The filesystem and version are what the probe observed; the storage class and driver come from
//! configuration, which never overrides what the probe observed, so the tuple is built here and
//! never taken from a caller. A tuple matches a qualified entry when its storage class, driver and
//! filesystem are equal and the entry's version is the running release or a prefix of it ending
//! before a `.` or a `-`: `6.8` covers `6.8.0-45-generic`, `6.8.0-45-generic` covers only itself. A
//! platform that meets the storage contract only as a compatibility mode (Windows) is never
//! qualified, whatever the registry says.

use permguard_core::assurance::AssuranceProfile;
use permguard_core::volume::{Tuple, VolumeConfig};

use super::probe::{Identity, Reason, Unsupported};
use super::{PlatformMode, platform_mode};

/// Where the volume stands.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Standing {
    /// A qualified tuple, and where its evidence is recorded.
    Qualified { evidence: String },
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

/// Whether the volume the probe observed as `identity` may serve under `profile`.
pub fn qualify(
    identity: &Identity,
    config: &VolumeConfig,
    profile: AssuranceProfile,
) -> Result<Standing, Unsupported> {
    qualify_on(platform_mode(), identity, config, profile)
}

fn qualify_on(
    platform: PlatformMode,
    identity: &Identity,
    config: &VolumeConfig,
    profile: AssuranceProfile,
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
        return Ok(Standing::Qualified {
            evidence: entry.evidence.clone(),
        });
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
        AssuranceProfile::Development if compatibility_platform => Ok(Standing::CompatibilityMode),
        AssuranceProfile::Development => Ok(Standing::Unqualified),
        AssuranceProfile::Production if config.compatibility_mode => {
            Ok(Standing::CompatibilityMode)
        }
        AssuranceProfile::Production if compatibility_platform => Err(refused(
            "runs on a platform that is only a compatibility mode, never qualified; under \
             `production` it needs storage.compatibility_mode set and published",
        )),
        AssuranceProfile::Production => Err(refused(
            "is not qualified for `production`; qualify it in storage.qualified, or set and \
             publish storage.compatibility_mode",
        )),
        AssuranceProfile::Regulated => Err(refused(
            "is not qualified, and `regulated` runs only on a qualified tuple",
        )),
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

    fn config(compatibility_mode: bool) -> VolumeConfig {
        VolumeConfig {
            storage_class: Some("fast-ssd".to_owned()),
            driver: Some("ebs.csi.aws.com".to_owned()),
            qualified: vec![QualifiedTuple {
                tuple: tuple("ext4"),
                evidence: "QUAL-2026-01".to_owned(),
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
                    evidence: "QUAL-2026-01".to_owned()
                })
            );
        }
    }

    #[test]
    fn an_unknown_tuple_is_reported_in_development_compatibility_in_production_and_refused_in_regulated()
     {
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
            on(true, AssuranceProfile::Production),
            Ok(Standing::CompatibilityMode)
        );
        for compatibility in [false, true] {
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
        assert_eq!(
            on(true, AssuranceProfile::Production),
            Ok(Standing::CompatibilityMode)
        );
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
}
