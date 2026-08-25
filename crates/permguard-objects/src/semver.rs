// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The closed semver-range grammar of the manifest — exactly three forms,
//! nothing else. `^`, `~` and `*` mean different things in different
//! ecosystems; two implementations parsing ranges differently would be the
//! version-drift bug one level up, so the grammar refuses them.
//!
//! ```text
//! >=x.y.z          any version from x.y.z upward
//! >=a.b.c <d.e.f   the half-open range [a.b.c, d.e.f)
//! x.y.z            exactly x.y.z
//! ```

use std::fmt;

/// One parsed version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Version {
    pub major: u64,
    pub minor: u64,
    pub patch: u64,
}

impl Version {
    /// Parses `x.y.z` — three dot-separated decimal numbers, nothing else.
    pub fn parse(text: &str) -> Result<Self, SemverError> {
        let mut parts = text.split('.');
        let mut next = || -> Result<u64, SemverError> {
            parts
                .next()
                .ok_or(SemverError::Grammar)?
                .parse::<u64>()
                .map_err(|_| SemverError::Grammar)
        };
        let version = Version {
            major: next()?,
            minor: next()?,
            patch: next()?,
        };
        if parts.next().is_some() {
            return Err(SemverError::Grammar);
        }
        Ok(version)
    }
}

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

/// One parsed constraint of the closed grammar.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Constraint {
    /// `x.y.z` — exactly.
    Exact(Version),
    /// `>=x.y.z` — from x.y.z upward.
    AtLeast(Version),
    /// `>=a.b.c <d.e.f` — the half-open range.
    Range(Version, Version),
}

impl Constraint {
    /// Parses the closed grammar; anything else is refused.
    pub fn parse(text: &str) -> Result<Self, SemverError> {
        let text = text.trim();
        if let Some(rest) = text.strip_prefix(">=") {
            let mut parts = rest.split_whitespace();
            let lower = Version::parse(parts.next().ok_or(SemverError::Grammar)?)?;
            match parts.next() {
                None => Ok(Constraint::AtLeast(lower)),
                Some(upper) => {
                    let upper = upper.strip_prefix('<').ok_or(SemverError::Grammar)?;
                    let upper = Version::parse(upper)?;
                    if parts.next().is_some() || upper <= lower {
                        return Err(SemverError::Grammar);
                    }
                    Ok(Constraint::Range(lower, upper))
                }
            }
        } else {
            Ok(Constraint::Exact(Version::parse(text)?))
        }
    }

    /// Whether a version satisfies this constraint.
    pub fn matches(&self, version: Version) -> bool {
        match self {
            Constraint::Exact(exact) => version == *exact,
            Constraint::AtLeast(lower) => version >= *lower,
            Constraint::Range(lower, upper) => version >= *lower && version < *upper,
        }
    }
}

impl fmt::Display for Constraint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Constraint::Exact(v) => write!(f, "{v}"),
            Constraint::AtLeast(v) => write!(f, ">={v}"),
            Constraint::Range(lower, upper) => write!(f, ">={lower} <{upper}"),
        }
    }
}

/// The one way this module refuses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SemverError {
    /// Not one of the three forms of the closed grammar.
    Grammar,
}

impl fmt::Display for SemverError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "a version constraint is `x.y.z`, `>=x.y.z` or `>=a.b.c <d.e.f` — nothing else"
        )
    }
}

impl std::error::Error for SemverError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(text: &str) -> Version {
        Version::parse(text).unwrap()
    }

    #[test]
    fn the_grammar_table_of_the_specification() {
        assert!(Constraint::parse(">=0.0.0").unwrap().matches(v("2.3.1")));
        let c = Constraint::parse(">=1.0.0").unwrap();
        assert!(c.matches(v("1.0.0")) && c.matches(v("2.0.0")) && !c.matches(v("0.9.9")));
        let c = Constraint::parse(">=1.0.0 <2.0.0").unwrap();
        assert!(c.matches(v("1.0.0")) && c.matches(v("1.9.9")));
        assert!(!c.matches(v("0.9.9")) && !c.matches(v("2.0.0")));
        let c = Constraint::parse("1.2.3").unwrap();
        assert!(c.matches(v("1.2.3")) && !c.matches(v("1.2.4")));
    }

    #[test]
    fn everything_else_is_refused() {
        for bad in [
            "^1.0.0",
            "~1.2",
            "*",
            "1.2",
            ">=1.0",
            ">=2.0.0 <1.0.0",
            "1.2.3.4",
            "",
        ] {
            assert!(Constraint::parse(bad).is_err(), "accepted: {bad}");
        }
    }
}
