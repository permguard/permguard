// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! How a person names a ledger on the command line: `<remote>/<zone>/<ledger>[@<ref>]`
//! for a tracked workspace, and a full URL for a clone.
//!
//! Syntax the CLI owns — a server never sees these shapes, it sees the
//! resolved parts.

pub fn parse_reference(text: &str) -> Result<(String, String, String, String), String> {
    let (path, r#ref) = match text.rsplit_once('@') {
        Some((path, r#ref)) if !r#ref.is_empty() => (path, r#ref.to_owned()),
        _ => (text, "main".to_owned()),
    };
    let parts: Vec<&str> = path.split('/').collect();
    if parts.len() != 3 || parts.iter().any(|part| part.is_empty()) {
        return Err("a reference is <remote>/<zone>/<ledger>[@<ref>]".to_owned());
    }
    Ok((
        parts[0].to_owned(),
        parts[1].to_owned(),
        parts[2].to_owned(),
        r#ref,
    ))
}

/// Parses a clone URL: the last two path segments are zone and ledger, the
/// rest is the server.
pub fn parse_clone_url(url: &str) -> Result<(String, String, String), String> {
    let (scheme, rest) = url.split_once("://").ok_or_else(|| {
        "a clone URL is https://host[:port][/prefix]/zone/ledger (or grpcs://…)".to_owned()
    })?;
    let mut segments: Vec<&str> = rest.split('/').filter(|part| !part.is_empty()).collect();
    if segments.len() < 3 {
        return Err("a clone URL ends in /<zone>/<ledger>".to_owned());
    }
    let (Some(ledger), Some(zone)) = (segments.pop(), segments.pop()) else {
        return Err("a clone URL ends in /<zone>/<ledger>".to_owned());
    };
    Ok((
        format!("{scheme}://{}", segments.join("/")),
        zone.to_owned(),
        ledger.to_owned(),
    ))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn references_parse() {
        let (remote, zone, ledger, r#ref) = parse_reference("origin/pharma/main-ledger").unwrap();
        assert_eq!(
            (
                remote.as_str(),
                zone.as_str(),
                ledger.as_str(),
                r#ref.as_str()
            ),
            ("origin", "pharma", "main-ledger", "main")
        );
        let (.., r#ref) = parse_reference("origin/pharma/main-ledger@feature/login").unwrap();
        assert_eq!(r#ref, "feature/login");
        assert!(parse_reference("just-a-name").is_err());
    }

    #[test]
    fn clone_urls_parse() {
        let (base, zone, ledger) =
            parse_clone_url("https://permguard.acme.com/pharma/main-ledger").unwrap();
        assert_eq!(base, "https://permguard.acme.com");
        assert_eq!((zone.as_str(), ledger.as_str()), ("pharma", "main-ledger"));
        let (base, ..) = parse_clone_url("https://saas.io/acme-corp/pharma/main-ledger").unwrap();
        assert_eq!(base, "https://saas.io/acme-corp");
    }
}
