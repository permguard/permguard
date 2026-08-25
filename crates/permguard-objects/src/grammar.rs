// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The normative grammars for tree-entry names and ref names. Both appear in
//! URLs and on disk, so they are parsed per segment and never concatenated
//! into paths unvalidated.

use std::fmt;

/// Validate a tree-entry name: one path segment, never a path.
/// Charset `a-z 0-9 . - _`, 1–128 bytes, starts and ends alphanumeric,
/// never `.` or `..`.
pub fn validate_entry_name(name: &str) -> Result<(), GrammarError> {
    let bytes = name.as_bytes();
    if bytes.is_empty() || bytes.len() > 128 {
        return Err(GrammarError::EntryName);
    }
    if name == "." || name == ".." {
        return Err(GrammarError::EntryName);
    }
    if !bytes
        .iter()
        .all(|c| matches!(c, b'a'..=b'z' | b'0'..=b'9' | b'.' | b'-' | b'_'))
    {
        return Err(GrammarError::EntryName);
    }
    let alnum = |c: u8| c.is_ascii_lowercase() || c.is_ascii_digit();
    if !alnum(bytes[0]) || !alnum(bytes[bytes.len() - 1]) {
        return Err(GrammarError::EntryName);
    }
    Ok(())
}

/// Validate a ref name: `/`-separated segments, charset `a-z 0-9 - _`,
/// each segment starts with a letter and ends alphanumeric (1–63 bytes),
/// total length ≤ 255 bytes, no empty segments.
pub fn validate_ref_name(name: &str) -> Result<(), GrammarError> {
    if name.is_empty() || name.len() > 255 {
        return Err(GrammarError::RefName);
    }
    if name.starts_with('/') || name.ends_with('/') {
        return Err(GrammarError::RefName);
    }
    for segment in name.split('/') {
        let bytes = segment.as_bytes();
        if bytes.is_empty() || bytes.len() > 63 {
            return Err(GrammarError::RefName);
        }
        if !bytes
            .iter()
            .all(|c| matches!(c, b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_'))
        {
            return Err(GrammarError::RefName);
        }
        if !bytes[0].is_ascii_lowercase() {
            return Err(GrammarError::RefName);
        }
        let last = bytes[bytes.len() - 1];
        if !(last.is_ascii_lowercase() || last.is_ascii_digit()) {
            return Err(GrammarError::RefName);
        }
    }
    Ok(())
}

/// Validate an annotation key: ≤ 128 bytes, charset `a-z 0-9 . - _`,
/// namespaced (contains at least one `.`), starts and ends alphanumeric.
pub fn validate_annotation_key(key: &str) -> Result<(), GrammarError> {
    let bytes = key.as_bytes();
    if bytes.is_empty() || bytes.len() > 128 || !key.contains('.') {
        return Err(GrammarError::AnnotationKey);
    }
    if !bytes
        .iter()
        .all(|c| matches!(c, b'a'..=b'z' | b'0'..=b'9' | b'.' | b'-' | b'_'))
    {
        return Err(GrammarError::AnnotationKey);
    }
    let alnum = |c: u8| c.is_ascii_lowercase() || c.is_ascii_digit();
    if !alnum(bytes[0]) || !alnum(bytes[bytes.len() - 1]) {
        return Err(GrammarError::AnnotationKey);
    }
    Ok(())
}

/// Which grammar rejected the input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GrammarError {
    EntryName,
    RefName,
    AnnotationKey,
}

impl fmt::Display for GrammarError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            GrammarError::EntryName => write!(
                f,
                "entry name must be a-z 0-9 . - _, 1-128 bytes, start and end alphanumeric, and not . or .."
            ),
            GrammarError::RefName => write!(
                f,
                "ref must be /-separated segments of a-z 0-9 - _, each starting with a letter and ending alphanumeric, at most 255 bytes"
            ),
            GrammarError::AnnotationKey => write!(
                f,
                "annotation key must be namespaced a-z 0-9 . - _, at most 128 bytes, start and end alphanumeric"
            ),
        }
    }
}

impl std::error::Error for GrammarError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entry_names() {
        for ok in ["billing-view.cedar", "a", "policy_1", "x.y.z"] {
            assert!(validate_entry_name(ok).is_ok(), "rejected: {ok}");
        }
        for bad in [
            "",
            ".",
            "..",
            ".hidden",
            "trailing.",
            "UPPER",
            "a/b",
            "a b",
            &"x".repeat(129),
        ] {
            assert!(validate_entry_name(bad).is_err(), "accepted: {bad}");
        }
    }

    #[test]
    fn ref_names() {
        for ok in ["main", "feature/login", "release/v1_2", "a1"] {
            assert!(validate_ref_name(ok).is_ok(), "rejected: {ok}");
        }
        for bad in [
            "", "/main", "main/", "a//b", "1main", "Main", "fea ture", "a.b", "-x", "x-",
        ] {
            assert!(validate_ref_name(bad).is_err(), "accepted: {bad}");
        }
    }

    #[test]
    fn annotation_keys() {
        assert!(validate_annotation_key("permguard.policy.id").is_ok());
        for bad in [
            "",
            "noname",
            ".x.y",
            "x.y.",
            "Perm.Guard",
            &format!("a.{}", "b".repeat(130)),
        ] {
            assert!(validate_annotation_key(bad).is_err(), "accepted: {bad}");
        }
    }
}
