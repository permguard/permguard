// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! Configuration a build adds that this crate knows nothing about.
//!
//! The typed settings of [`Config`](crate::config::Config) are the ones every build has. Anything a
//! particular build adds — a signing scheme, an identity provider, a rate limiter, a feature that does
//! not exist yet — arrives as a section of the configuration file, parsed into a type that lives in
//! the crate that needs it.
//!
//! The mechanism is deliberately not about keys. Keys are simply the first thing that needed it: a
//! nested, typed, validated section is what a list of key scopes requires, and what a flat
//! `(String, String)` setting could never express.
//!
//! ```ignore
//! #[derive(Debug, Deserialize)]
//! struct SigningConfig {
//!     scopes: BTreeMap<String, ScopeConfig>,
//! }
//!
//! impl ConfigSection for SigningConfig {
//!     const NAME: &'static str = "signing";
//!
//!     fn validate(&self) -> Result<()> {
//!         // Whatever "makes sense" means for this section, checked before the server starts.
//!         Ok(())
//!     }
//! }
//!
//! // composed once, in the binary
//! App::new(/* … */).with_config_section::<SigningConfig>()
//!
//! // read back anywhere there is a &Config — including from a service the core never heard of
//! let signing = config.section::<SigningConfig>();
//! ```

use std::any::Any;
use std::fmt;

use anyhow::{Context, Result};
use serde::de::DeserializeOwned;

/// A typed configuration-file section a build adds.
///
/// Implementations are plain deserialisable types. Registering one claims its section name, so a file
/// that declares it is accepted and a file that misspells it is still rejected.
pub trait ConfigSection: DeserializeOwned + fmt::Debug + Send + Sync + 'static {
    /// The name of the configuration-file section this type is parsed from.
    const NAME: &'static str;

    /// Checks the section makes sense on its own, before anything is started.
    ///
    /// This runs at load time, so a misconfigured build fails where a human is watching rather than
    /// at the first request.
    fn validate(&self) -> Result<()> {
        Ok(())
    }

    /// Parses and validates the section out of the value the configuration file held.
    ///
    /// Provided here rather than at the call site so that a crate registering a section does not have
    /// to depend on the deserialisation crate this one happens to use.
    fn parse(value: &crate::Value) -> Result<Self> {
        let section: Self = serde_norway::from_value(value.clone())
            .with_context(|| format!("reading the `{}` section", Self::NAME))?;

        section
            .validate()
            .with_context(|| format!("validating the `{}` section", Self::NAME))?;

        Ok(section)
    }
}

/// A parsed section, kept without the parsing crate having to know its type.
///
/// The supertraits are what let [`Config`](crate::config::Config) keep its own `Debug` and stay
/// shareable across tasks while holding types it has never seen.
pub trait AnyConfigSection: Any + fmt::Debug + Send + Sync {
    /// Returns this section as `Any`, so the caller can ask for the type it registered.
    fn as_any(&self) -> &dyn Any;

    /// Returns the name of the section this was parsed from.
    fn section_name(&self) -> &'static str;
}

impl<T: ConfigSection> AnyConfigSection for T {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn section_name(&self) -> &'static str {
        T::NAME
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;

    use std::sync::Arc;

    use anyhow::bail;
    use serde::Deserialize;

    /// A section of the kind a crate outside this workspace would define.
    #[derive(Debug, Deserialize, PartialEq, Eq)]
    struct SigningConfig {
        algorithm: String,
        #[serde(default)]
        rotation: Option<String>,
    }

    impl ConfigSection for SigningConfig {
        const NAME: &'static str = "signing";

        fn validate(&self) -> Result<()> {
            if self.algorithm.is_empty() {
                bail!("the signing algorithm is empty");
            }

            Ok(())
        }
    }

    fn parse(text: &str) -> SigningConfig {
        let value: serde_norway::Value = serde_norway::from_str(text).expect("the section parses");

        serde_norway::from_value(value).expect("the section deserialises")
    }

    #[test]
    fn test_a_section_defined_outside_this_crate_parses_into_its_own_type() {
        let parsed = parse("algorithm: ES256\nrotation: 6h\n");

        assert_eq!(
            parsed,
            SigningConfig {
                algorithm: "ES256".to_owned(),
                rotation: Some("6h".to_owned()),
            }
        );
    }

    #[test]
    fn test_a_section_validates_itself() {
        assert!(parse("algorithm: ES256\n").validate().is_ok());
        assert!(parse("algorithm: ''\n").validate().is_err());
    }

    #[test]
    fn test_a_kept_section_hands_its_own_type_back() {
        let kept: Arc<dyn AnyConfigSection> = Arc::new(parse("algorithm: ES256\n"));

        assert_eq!(kept.section_name(), "signing");
        assert_eq!(
            kept.as_any()
                .downcast_ref::<SigningConfig>()
                .expect("the type comes back")
                .algorithm,
            "ES256"
        );
    }

    #[test]
    fn test_asking_for_the_wrong_type_yields_nothing_rather_than_the_wrong_thing() {
        let kept: Arc<dyn AnyConfigSection> = Arc::new(parse("algorithm: ES256\n"));

        assert!(kept.as_any().downcast_ref::<String>().is_none());
    }
}
