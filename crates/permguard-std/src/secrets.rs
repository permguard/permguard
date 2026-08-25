// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! Where secret material actually comes from.
//!
//! Two implementations, both deliberately humble, because the point of the contract is that neither
//! of them is the interesting one. The interesting one is Vault, or a KMS, or an HSM — and it lives
//! outside this workspace, in a build that needs it.
//!
//! # What a reference is
//!
//! Configuration names a secret; it does not contain one. `audit.pseudonym.key_ref: audit-pseudonym`
//! says *which* secret, and the store says what it is. That distinction is the whole design:
//!
//! * a configuration file stops being a file that must be protected like a key;
//! * the same configuration works against a directory in development and against Vault in
//!   production, because only the store changes;
//! * a key rotates where keys live, not by editing YAML and redeploying.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use permguard_core::{Secret, SecretError, SecretRef, SecretStore};

/// What these stores answer with.
type Result<T> = std::result::Result<T, SecretError>;

/// Resolves each reference to a file of the same name in one directory.
///
/// This is what a Kubernetes secret mounted as a volume looks like from inside a container: one file
/// per key, named after it. It is therefore not a toy — it is the deployment most clusters actually
/// use — but it is still material on a filesystem, and anything that reads the filesystem reads it.
#[derive(Debug, Clone)]
pub struct DirectorySecretStore {
    directory: PathBuf,
}

impl DirectorySecretStore {
    /// Resolves references against files under `directory`.
    pub fn new(directory: impl Into<PathBuf>) -> Self {
        Self {
            directory: directory.into(),
        }
    }

    /// Returns the path a reference resolves to.
    ///
    /// A reference that tries to leave the directory resolves to nothing rather than to a file
    /// somewhere else: `../../etc/shadow` is not a secret name, it is an attempt.
    fn path_of(&self, reference: &SecretRef) -> Option<PathBuf> {
        let name = reference.name();

        if name.is_empty()
            || name.contains("..")
            || name.contains('/')
            || name.contains('\\')
            || Path::new(name).is_absolute()
        {
            return None;
        }

        Some(self.directory.join(name))
    }
}

impl SecretStore for DirectorySecretStore {
    fn name(&self) -> &'static str {
        "directory"
    }

    fn resolve(&self, reference: &SecretRef) -> Result<Secret> {
        let Some(path) = self.path_of(reference) else {
            // Refused rather than "not found": the reference is not merely absent, it is malformed,
            // and answering the same way would hide an attempt inside ordinary noise.
            return Err(SecretError::Denied {
                reference: reference.name().to_owned(),
            });
        };

        check_permissions(&path, reference)?;

        match std::fs::read(&path) {
            Ok(material) => Ok(Secret::new(trim_trailing_newline(material))),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                Err(SecretError::NotFound {
                    reference: reference.name().to_owned(),
                })
            }
            Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => {
                Err(SecretError::Denied {
                    reference: reference.name().to_owned(),
                })
            }
            Err(error) => Err(SecretError::unavailable(error)),
        }
    }
}

/// Resolves each reference to an environment variable of the same name, upper-cased.
///
/// Weaker than a file — the environment of a process is readable by anything that can read `/proc`,
/// and it is inherited by every child — so this exists for development and for the deployments that
/// have nothing else, and says so.
#[derive(Debug, Clone, Default)]
pub struct EnvironmentSecretStore {
    prefix: String,
}

impl EnvironmentSecretStore {
    /// Resolves references against variables named `PREFIX_REFERENCE`.
    pub fn new(prefix: impl Into<String>) -> Self {
        Self {
            prefix: prefix.into(),
        }
    }

    /// Returns the variable name a reference resolves to.
    fn variable_of(&self, reference: &SecretRef) -> String {
        let name = reference.name().replace(['-', '.'], "_").to_uppercase();

        if self.prefix.is_empty() {
            name
        } else {
            format!("{}_{name}", self.prefix)
        }
    }
}

impl SecretStore for EnvironmentSecretStore {
    fn name(&self) -> &'static str {
        "environment"
    }

    fn resolve(&self, reference: &SecretRef) -> Result<Secret> {
        match std::env::var(self.variable_of(reference)) {
            Ok(material) => Ok(Secret::new(material.into_bytes())),
            Err(_) => Err(SecretError::NotFound {
                reference: reference.name().to_owned(),
            }),
        }
    }
}

/// Holds material given to it, for tests and for a build that has nowhere better yet.
///
/// It ships outside `cfg(test)` because a binary built on these crates needs to test its own
/// composition, and reimplementing this in every such build is how subtle differences creep in.
#[derive(Debug, Clone, Default)]
pub struct InMemorySecretStore {
    secrets: BTreeMap<String, Vec<u8>>,
}

impl InMemorySecretStore {
    /// Builds an empty store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds material under `reference`.
    pub fn with(mut self, reference: &str, material: impl Into<Vec<u8>>) -> Self {
        self.secrets.insert(reference.to_owned(), material.into());

        self
    }
}

impl SecretStore for InMemorySecretStore {
    fn name(&self) -> &'static str {
        "in-memory"
    }

    fn resolve(&self, reference: &SecretRef) -> Result<Secret> {
        self.secrets
            .get(reference.name())
            .map(|material| Secret::new(material.clone()))
            .ok_or_else(|| SecretError::NotFound {
                reference: reference.name().to_owned(),
            })
    }
}

/// Refuses material anyone on the host could rewrite, and says so about material they could read.
///
/// The two cases are not the same and must not be treated the same. **Writable** by others means an
/// attacker chooses the key — every signature, every pseudonym, every derived value becomes theirs —
/// so it is refused. **Readable** by others is a weaker posture and, at 0644, is what a Kubernetes
/// secret volume mounts by default; refusing it would refuse the most common correct deployment, so
/// it is reported and allowed.
///
/// On a platform without Unix permissions there is nothing to check and nothing is claimed.
#[cfg(unix)]
fn check_permissions(path: &Path, reference: &SecretRef) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let Ok(metadata) = std::fs::metadata(path) else {
        // Whatever is wrong with it, reading is about to report it properly.
        return Ok(());
    };

    let mode = metadata.permissions().mode();

    if mode & 0o022 != 0 {
        return Err(SecretError::Denied {
            reference: reference.name().to_owned(),
        });
    }

    if mode & 0o044 != 0 {
        tracing::warn!(
            event.name = "secret.permissive",
            component = "secrets",
            secret.reference = reference.name(),
            mode = format!("{:o}", mode & 0o777),
            "the secret is readable by users other than the one running this process"
        );
    }

    Ok(())
}

#[cfg(not(unix))]
fn check_permissions(_path: &Path, _reference: &SecretRef) -> Result<()> {
    Ok(())
}

/// Drops the newline a file ends with, which almost every editor adds and no key contains.
fn trim_trailing_newline(mut material: Vec<u8>) -> Vec<u8> {
    if material.last() == Some(&b'\n') {
        material.pop();
    }
    if material.last() == Some(&b'\r') {
        material.pop();
    }

    material
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_a_reference_that_tries_to_escape_the_directory_is_refused() {
        let store = DirectorySecretStore::new("/var/run/secrets");

        for attempt in ["../../etc/shadow", "/etc/shadow", "a/b", ""] {
            assert!(
                store.path_of(&SecretRef::new(attempt)).is_none(),
                "`{attempt}` resolved to a path"
            );
        }
    }

    #[test]
    fn test_a_plain_reference_resolves_inside_the_directory() {
        let store = DirectorySecretStore::new("/var/run/secrets");

        assert_eq!(
            store.path_of(&SecretRef::new("audit-pseudonym")),
            Some(PathBuf::from("/var/run/secrets/audit-pseudonym"))
        );
    }

    #[test]
    fn test_a_reference_becomes_a_variable_name() {
        let store = EnvironmentSecretStore::new("PERMGUARD_SECRET");

        assert_eq!(
            store.variable_of(&SecretRef::new("audit-pseudonym")),
            "PERMGUARD_SECRET_AUDIT_PSEUDONYM"
        );
    }
}
