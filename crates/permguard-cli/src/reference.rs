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
    named("zone", parts[1])?;
    named("ledger", parts[2])?;
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
    named("zone", zone)?;
    named("ledger", ledger)?;
    Ok((
        format!("{scheme}://{}", segments.join("/")),
        zone.to_owned(),
        ledger.to_owned(),
    ))
}

/// Checks that `value` names a zone or a ledger the catalog could hold: its id, or a name the
/// catalog accepts (BUG-0251, DEC-0017). A query or a fragment folded into it (`orders?view=1`,
/// `orders#top`) names no ledger, and would be recorded, and made a folder, as if it did.
fn named(kind: &str, value: &str) -> Result<(), String> {
    if let Some(at) = value.find(['?', '#']) {
        return Err(format!(
            "the {kind} `{value}` carries a {} (`{}`), which names no ledger: remove it",
            if value[at..].starts_with('?') {
                "query"
            } else {
                "fragment"
            },
            &value[at..]
        ));
    }
    if permguard_core::catalog::is_guid_shaped(value) {
        return Ok(());
    }
    permguard_core::catalog::validate_name(value)
        .map_err(|error| format!("`{value}` is not a {kind} name or id: {error}"))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn references_parse() {
        let (remote, zone, ledger, r#ref) = parse_reference("origin/delivery/main-ledger").unwrap();
        assert_eq!(
            (
                remote.as_str(),
                zone.as_str(),
                ledger.as_str(),
                r#ref.as_str()
            ),
            ("origin", "delivery", "main-ledger", "main")
        );
        let (.., r#ref) = parse_reference("origin/delivery/main-ledger@feature/login").unwrap();
        assert_eq!(r#ref, "feature/login");
        assert!(parse_reference("just-a-name").is_err());
    }

    #[test]
    fn clone_urls_parse() {
        let (base, zone, ledger) =
            parse_clone_url("https://permguard.acme.com/delivery/main-ledger").unwrap();
        assert_eq!(base, "https://permguard.acme.com");
        assert_eq!(
            (zone.as_str(), ledger.as_str()),
            ("delivery", "main-ledger")
        );
        let (base, ..) = parse_clone_url("https://saas.io/acme-corp/delivery/main-ledger").unwrap();
        assert_eq!(base, "https://saas.io/acme-corp");
    }

    /// BUG-0251: a query or a fragment is never folded into the ledger, and a zone or ledger is
    /// a name the catalog accepts or an id.
    #[test]
    fn a_query_or_fragment_is_refused_and_names_are_checked() {
        for url in [
            "http://127.0.0.1:52443/shop/orders?view=1",
            "http://127.0.0.1:52443/shop/orders#top",
        ] {
            let refused = parse_clone_url(url).unwrap_err();
            assert!(
                refused.contains("query") || refused.contains("fragment"),
                "{refused}"
            );
        }
        let refused = parse_reference("origin/shop/orders?view=1").unwrap_err();
        assert!(refused.contains("query"), "{refused}");
        assert!(parse_reference("origin/Shop/orders").is_err());
        assert!(
            parse_reference("origin/0f8e2a10-2c4b-4d7e-9a61-3b5c7d9e1f20/orders").is_ok(),
            "an id is accepted"
        );
    }
}
