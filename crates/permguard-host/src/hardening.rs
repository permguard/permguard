// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! Bootstrap's check of the process and the volume it owns (TS-5), before anything is served.
//!
//! | Check                                      | `development` | `production` and `regulated` | Code                  |
//! | ------------------------------------------ | ------------- | ---------------------------- | --------------------- |
//! | the process runs as a dedicated user       | reported      | refused if root              | `storage_run_as_root` |
//! | core dumps disabled and read back          | reported      | refused                      | `storage_core_dumps`  |
//! | every volume entry owned by the process    | reported      | refused                      | `storage_owner`       |
//! | directories `0700`, files `0600`           | reported      | refused                      | `storage_mode`        |
//! | no symbolic link, the root not reached by one | reported   | refused                      | `storage_link`        |
//! | only directories and regular files         | reported      | refused                      | `storage_file_kind`   |
//! | no other filesystem mounted inside         | reported      | refused                      | `storage_path_escape` |
//!
//! Core dumps are disabled under every profile; only a disabling that did not take is judged by
//! the profile. A volume that cannot be walked at all is refused from `production` like a breach.
//! Reported means logged at Bootstrap with its code, so `development` sees what `production` would
//! refuse.

use std::path::Path;

use permguard_core::assurance::AssuranceProfile;
use permguard_core::codes::storage;

use crate::process;
use crate::storage::private::{self, Inspection};

/// One check that did not pass, with its registered code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Shortfall {
    pub code: &'static str,
    pub detail: String,
}

impl std::fmt::Display for Shortfall {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code, self.detail)
    }
}

/// What the checks found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Facts {
    pub uid: Option<u32>,
    /// Whether core dumps were disabled, and why not.
    pub core_dumps: Result<(), String>,
    /// The volume's walk, or why it could not be walked.
    pub volume: Result<Inspection, String>,
}

/// A process and volume the profile accepts, with what it accepted without being satisfied.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hardened {
    pub directories: u64,
    pub files: u64,
    /// What `development` accepts and `production` would refuse.
    pub reported: Vec<Shortfall>,
}

/// A process or volume the profile refuses: every shortfall, the first one first.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refused {
    pub profile: AssuranceProfile,
    pub shortfalls: Vec<Shortfall>,
    /// The volume's findings past those listed.
    pub more: u64,
}

impl Refused {
    /// The code of the first shortfall: the one an operator fixes first.
    pub fn code(&self) -> &'static str {
        self.shortfalls
            .first()
            .map_or(storage::MODE, |shortfall| shortfall.code)
    }
}

impl std::fmt::Display for Refused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "the `{}` profile does not serve this process and volume:",
            self.profile
        )?;
        for shortfall in &self.shortfalls {
            write!(f, "\n  {shortfall}")?;
        }
        if self.more > 0 {
            write!(f, "\n  and {} more entries of the volume", self.more)?;
        }
        Ok(())
    }
}

impl std::error::Error for Refused {}

/// Disables core dumps, walks the volume at `root` and judges both under `profile`.
pub fn harden(root: &Path, profile: AssuranceProfile) -> Result<Hardened, Refused> {
    // What this process creates from here on is its owner's alone, the volume itself included.
    private::restrict_creation_mask();
    assess(
        profile,
        Facts {
            uid: process::effective_uid(),
            core_dumps: process::disable_core_dumps(),
            volume: private::inspect(root).map_err(|error| error.to_string()),
        },
    )
}

/// Judges what the checks found under `profile`.
pub fn assess(profile: AssuranceProfile, facts: Facts) -> Result<Hardened, Refused> {
    let mut shortfalls = Vec::new();
    if facts.uid == Some(0) {
        shortfalls.push(Shortfall {
            code: storage::RUN_AS_ROOT,
            detail: "the process runs as root; run it as a dedicated user that owns the volume"
                .to_owned(),
        });
    }
    if let Err(why) = facts.core_dumps {
        shortfalls.push(Shortfall {
            code: storage::CORE_DUMPS,
            detail: format!("core dumps are not disabled: {why}"),
        });
    }
    let (mut directories, mut files, mut more) = (0, 0, 0);
    match facts.volume {
        Ok(inspection) => {
            directories = inspection.directories;
            files = inspection.files;
            more = inspection.more;
            shortfalls.extend(inspection.findings.iter().map(|finding| Shortfall {
                code: finding.breach.code(),
                detail: format!("{}: {}", finding.path.display(), finding.detail),
            }));
        }
        Err(why) => shortfalls.push(Shortfall {
            code: storage::MODE,
            detail: format!("the volume could not be walked to verify it is private: {why}"),
        }),
    }
    if profile.at_least(AssuranceProfile::Production) && !shortfalls.is_empty() {
        return Err(Refused {
            profile,
            shortfalls,
            more,
        });
    }
    Ok(Hardened {
        directories,
        files,
        reported: shortfalls,
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use std::path::PathBuf;

    use super::*;
    use crate::storage::private::{Breach, Finding};

    fn private_facts() -> Facts {
        Facts {
            uid: Some(65532),
            core_dumps: Ok(()),
            volume: Ok(Inspection {
                directories: 3,
                files: 2,
                ..Inspection::default()
            }),
        }
    }

    const PROFILES: [AssuranceProfile; 3] = [
        AssuranceProfile::Development,
        AssuranceProfile::Production,
        AssuranceProfile::Regulated,
    ];

    #[test]
    fn a_private_process_and_volume_serve_under_every_profile() {
        for profile in PROFILES {
            let hardened = assess(profile, private_facts()).expect("served");
            assert_eq!((hardened.directories, hardened.files), (3, 2));
            assert!(hardened.reported.is_empty());
        }
    }

    /// Every shortfall, alone: reported under `development`, refused with its code above.
    #[test]
    fn each_shortfall_is_refused_from_production_and_reported_below() {
        let breach = |breach: Breach| {
            let mut facts = private_facts();
            facts.volume = Ok(Inspection {
                findings: vec![Finding {
                    breach,
                    path: PathBuf::from("/v/host/x"),
                    detail: "found".to_owned(),
                }],
                ..Inspection::default()
            });
            facts
        };
        let cases: Vec<(&str, Facts)> = vec![
            (
                "storage_run_as_root",
                Facts {
                    uid: Some(0),
                    ..private_facts()
                },
            ),
            (
                "storage_core_dumps",
                Facts {
                    core_dumps: Err("the limit reads 1".to_owned()),
                    ..private_facts()
                },
            ),
            ("storage_owner", breach(Breach::Owner)),
            ("storage_mode", breach(Breach::Mode)),
            ("storage_link", breach(Breach::Link)),
            ("storage_file_kind", breach(Breach::Kind)),
            ("storage_path_escape", breach(Breach::Escape)),
            (
                "storage_mode",
                Facts {
                    volume: Err("permission denied".to_owned()),
                    ..private_facts()
                },
            ),
        ];
        for (code, facts) in cases {
            let reported = assess(AssuranceProfile::Development, facts.clone())
                .expect("development serves it");
            assert_eq!(reported.reported.len(), 1, "{code}");
            assert_eq!(reported.reported[0].code, code);
            for profile in [AssuranceProfile::Production, AssuranceProfile::Regulated] {
                let refused = assess(profile, facts.clone()).expect_err("refused");
                assert_eq!(refused.code(), code);
                assert!(refused.to_string().contains(code), "{refused}");
            }
        }
    }

    #[test]
    fn a_refusal_lists_every_shortfall_and_counts_the_rest() {
        let facts = Facts {
            uid: Some(0),
            core_dumps: Err("dumpable".to_owned()),
            volume: Ok(Inspection {
                findings: vec![Finding {
                    breach: Breach::Mode,
                    path: PathBuf::from("/v/host"),
                    detail: "mode 0755".to_owned(),
                }],
                more: 7,
                ..Inspection::default()
            }),
        };
        let refused = assess(AssuranceProfile::Production, facts).expect_err("refused");
        let codes: Vec<&str> = refused.shortfalls.iter().map(|s| s.code).collect();
        assert_eq!(
            codes,
            ["storage_run_as_root", "storage_core_dumps", "storage_mode"]
        );
        assert!(
            refused
                .to_string()
                .ends_with("and 7 more entries of the volume")
        );
    }

    /// The real checks against a real volume: the scratch directory this process creates is its
    /// own and, under the creation mask, private.
    #[cfg(unix)]
    #[test]
    fn harden_disables_core_dumps_and_walks_the_volume() {
        let root = std::env::temp_dir().join(format!(
            "pg-host-hardening-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        private::restrict_creation_mask();
        std::fs::create_dir_all(root.join("host")).expect("creates");
        std::fs::write(root.join("host/file"), b"x").expect("writes");
        let hardened = harden(&root, AssuranceProfile::Development).expect("served");
        process::core_dumps_disabled().expect("core dumps are now disabled");
        if !process::runs_as_root() {
            assert!(hardened.reported.is_empty(), "{:?}", hardened.reported);
            harden(&root, AssuranceProfile::Production).expect("and served from production");
        }
        assert_eq!((hardened.directories, hardened.files), (2, 1));
        let _ = std::fs::remove_dir_all(&root);
    }
}
