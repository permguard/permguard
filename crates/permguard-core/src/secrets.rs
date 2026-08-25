// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The secret-material contract, deliberately separate from [`Storage`](crate::storage::Storage).
//!
//! Records and secrets look alike — both are bytes under a name — and that resemblance is exactly
//! what makes a single contract dangerous. A record store is expected to persist what it is given
//! wherever it persists things; a secret store is expected to never do that. Keeping the two
//! contracts apart is what lets a build put records in Postgres and secrets in Vault, and what stops
//! a key from reaching a backend that was only ever meant to hold records.
//!
//! There is no implementation of this contract in the workspace yet. It is defined now because the
//! separation has to exist before the first secret does.

use std::fmt;
use std::str::FromStr;

use crate::error::SecretError;

/// What a secret store answers with.
pub type Result<T> = std::result::Result<T, SecretError>;

/// Where a deployment resolves its secrets from.
///
/// An enum in configuration, a trait in code: this names which implementation a binary should build,
/// and the binary is still the only place that names the type. A build with a store this does not
/// list adds it in its own composition root without changing anything here.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SecretProvider {
    /// No store at all, which is the honest default: nothing here needs one until it is configured.
    #[default]
    None,
    /// One file per secret in a directory — what a mounted Kubernetes secret looks like.
    Directory,
    /// One environment variable per secret. Weaker, and for the deployments that have nothing else.
    Environment,
}

impl SecretProvider {
    /// Returns the name this provider is written as.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Directory => "directory",
            Self::Environment => "environment",
        }
    }

    /// Every provider a configuration may name.
    pub const ALL: [Self; 3] = [Self::None, Self::Directory, Self::Environment];
}

impl FromStr for SecretProvider {
    type Err = anyhow::Error;

    fn from_str(value: &str) -> anyhow::Result<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "none" | "" => Ok(Self::None),
            "directory" | "dir" | "file" => Ok(Self::Directory),
            "environment" | "env" => Ok(Self::Environment),
            other => anyhow::bail!(
                "`{other}` is not a secret provider: expected one of {}",
                Self::ALL.map(|provider| provider.as_str()).join(", ")
            ),
        }
    }
}

impl fmt::Display for SecretProvider {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// The name of a secret, as configuration refers to it.
///
/// A reference is not sensitive: it names the material without carrying it, so it may be logged.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SecretRef(String);

impl SecretRef {
    /// Builds a reference to the secret named `name`.
    pub fn new(name: impl Into<String>) -> Self {
        Self(name.into())
    }

    /// Returns the name this reference resolves.
    pub fn name(&self) -> &str {
        &self.0
    }
}

/// Resolved secret material.
///
/// The type implements neither `Debug` nor `Display` nor `Clone`: it cannot reach a log by accident,
/// and every copy is a decision someone had to write down. Reading the bytes goes through
/// [`Secret::expose`], which is named to be conspicuous in review.
///
/// # What is erased, and what that is worth
///
/// The buffer is zeroized when the value is dropped, with volatile writes the optimiser is not
/// allowed to elide — which is what `zeroize` exists for, and why this is not hand-rolled. It shortens
/// the window in which a key sits in a core dump, a swap file or a hibernation image to the time the
/// process actually needed it.
///
/// It is a real reduction and not a guarantee. The allocator may already have moved the bytes while
/// the `Vec` grew, the kernel may have paged the old copy out, and anything obtained through
/// [`Secret::expose`] is an ordinary slice this type no longer governs. So it is worth doing, worth
/// doing correctly, and not worth believing more than it says.
#[derive(zeroize::ZeroizeOnDrop)]
pub struct Secret {
    material: Vec<u8>,
}

impl Secret {
    /// Wraps resolved material.
    pub fn new(material: Vec<u8>) -> Self {
        Self { material }
    }

    /// Returns the material. Every call site is a place a secret leaves this type.
    pub fn expose(&self) -> &[u8] {
        &self.material
    }

    /// Returns the number of bytes of material, which is not itself sensitive.
    pub fn len(&self) -> usize {
        self.material.len()
    }

    /// Reports whether the material is empty.
    pub fn is_empty(&self) -> bool {
        self.material.is_empty()
    }
}

/// The source secret material is resolved from.
///
/// Implementations are shared across tasks, so they are `Send + Sync` and take `&self`.
pub trait SecretStore: Send + Sync {
    /// Returns the name of this implementation, for banners and diagnostics.
    fn name(&self) -> &'static str;

    /// Resolves `reference` to its material, or reports why it could not be resolved.
    ///
    /// The three ways it can fail are three different decisions for the caller: a reference that does
    /// not exist is a configuration mistake, a refusal is a policy decision, and a store that is down
    /// is worth retrying. A build that cannot tell them apart either fails open during an outage or
    /// fails shut forever — which is why this does not return an opaque error.
    fn resolve(&self, reference: &SecretRef) -> Result<Secret>;
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;

    /// A store written against the contract from outside any implementation crate.
    struct StubStore;

    impl SecretStore for StubStore {
        fn name(&self) -> &'static str {
            "stub"
        }

        fn resolve(&self, reference: &SecretRef) -> Result<Secret> {
            Ok(Secret::new(reference.name().as_bytes().to_vec()))
        }
    }

    #[test]
    fn test_a_reference_names_the_material_without_carrying_it() {
        let reference = SecretRef::new("signing-key");

        assert_eq!(reference.name(), "signing-key");
        assert_eq!(format!("{reference:?}"), r#"SecretRef("signing-key")"#);
    }

    #[test]
    fn test_the_contract_is_implementable_from_outside_and_usable_as_a_trait_object() {
        let store: Box<dyn SecretStore> = Box::new(StubStore);

        let secret = store
            .resolve(&SecretRef::new("signing-key"))
            .expect("the reference resolves");

        assert_eq!(store.name(), "stub");
        assert_eq!(secret.expose(), b"signing-key");
        assert_eq!(secret.len(), 11);
        assert!(!secret.is_empty());
    }

    #[test]
    fn test_empty_material_reads_back_as_empty() {
        let secret = Secret::new(Vec::new());

        assert!(secret.is_empty());
        assert_eq!(secret.len(), 0);
    }
}
