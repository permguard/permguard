// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The assurance profiles: `development` ⊂ `production` ⊂ `regulated`.
//!
//! A deployment states one word and every control of that profile is in force; a control names the
//! lowest profile that requires it, and a check asks whether the running profile is at least that
//! one. The order is the type's: `Development < Production < Regulated`.
//!
//! The configuration key that states the profile and the Bootstrap check that enforces it arrive
//! with the Host composition (WP-2.1); until then the controls that depend on a profile take it as an
//! argument.

use std::fmt;
use std::str::FromStr;

/// One of the three assurance profiles, ordered from the least to the most demanding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AssuranceProfile {
    /// Somebody's laptop or a test environment: the controls that cost nothing still hold.
    Development,
    /// The floor for any Host that serves real decisions.
    Production,
    /// What a regulated industry or a security audit requires on top of `production`.
    Regulated,
}

impl AssuranceProfile {
    /// The word a deployment writes for this profile.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Development => "development",
            Self::Production => "production",
            Self::Regulated => "regulated",
        }
    }

    /// Whether this profile includes every control of `floor`.
    pub fn at_least(self, floor: Self) -> bool {
        self >= floor
    }
}

impl fmt::Display for AssuranceProfile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for AssuranceProfile {
    type Err = String;

    /// Reads one of the three words, and nothing else: the retired spellings (`strict`,
    /// `high-assurance`, `security-critical`) are refused rather than mapped.
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.trim() {
            "development" => Ok(Self::Development),
            "production" => Ok(Self::Production),
            "regulated" => Ok(Self::Regulated),
            other => Err(format!(
                "`{other}` is not an assurance profile: expected development, production or \
                 regulated"
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_the_profiles_are_ordered_and_read_back_by_their_words() {
        assert!(AssuranceProfile::Development < AssuranceProfile::Production);
        assert!(AssuranceProfile::Production < AssuranceProfile::Regulated);
        assert!(AssuranceProfile::Regulated.at_least(AssuranceProfile::Production));
        assert!(!AssuranceProfile::Development.at_least(AssuranceProfile::Production));
        for profile in [
            AssuranceProfile::Development,
            AssuranceProfile::Production,
            AssuranceProfile::Regulated,
        ] {
            assert_eq!(profile.to_string().parse::<AssuranceProfile>(), Ok(profile));
        }
        for refused in ["strict", "high-assurance", "Production", ""] {
            assert!(refused.parse::<AssuranceProfile>().is_err(), "{refused:?}");
        }
    }
}
