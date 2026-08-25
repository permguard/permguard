// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! Who is on the other end of a mutually authenticated connection.
//!
//! Mutual TLS answers one question — *was this certificate signed by an authority we trust* — and
//! deployments routinely mistake it for a second one: *is this client allowed to do what it is
//! asking*. They are not the same question. One certificate authority signs every client it was
//! built to serve, so a surface that stops at the handshake grants everything to everyone that
//! authority ever signed.
//!
//! This module carries the answer to the first question in a form the second one can be asked
//! against: what the certificate said the client is, and what the certificate itself is.
//!
//! # Why both a name and a fingerprint
//!
//! They fail in opposite directions, and a deployment needs to choose which failure it prefers.
//!
//! * A **name** survives renewal. The certificate is reissued every ninety days and the allowlist
//!   keeps working — but anyone who can persuade the authority to sign that name is now that client.
//! * A **fingerprint** names one certificate and nothing else. Nobody can be impersonated by
//!   obtaining a certificate with the same subject — but every renewal is an allowlist edit, and an
//!   allowlist nobody updates is an outage.
//!
//! Neither is right for every deployment, so both are expressible and the deployment says which.

use std::fmt;
use std::str::FromStr;

use anyhow::{Result, bail};

/// What the certificate at the other end of a connection said about its holder.
///
/// Produced by whatever terminates TLS, read by whatever authorises. It holds only what the
/// certificate itself asserted: nothing here is a decision, and nothing here is secret — a client
/// certificate is presented in the clear on every connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerIdentity {
    subject: String,
    common_name: Option<String>,
    fingerprint: String,
    serial: String,
}

impl PeerIdentity {
    /// Records what a certificate asserted.
    ///
    /// `fingerprint` is the SHA-256 of the certificate as presented, lowercase hex — the value every
    /// other tool prints, so an allowlist entry can be copied from `openssl x509 -fingerprint`
    /// without being reformatted by hand.
    pub fn new(
        subject: impl Into<String>,
        common_name: Option<String>,
        fingerprint: impl Into<String>,
        serial: impl Into<String>,
    ) -> Self {
        Self {
            subject: subject.into(),
            common_name,
            fingerprint: fingerprint.into(),
            serial: serial.into(),
        }
    }

    /// Returns the distinguished name the certificate carried, in RFC 4514 form.
    pub fn subject(&self) -> &str {
        &self.subject
    }

    /// Returns the common name, when the subject has one.
    pub fn common_name(&self) -> Option<&str> {
        self.common_name.as_deref()
    }

    /// Returns the SHA-256 of the presented certificate, lowercase hex.
    pub fn fingerprint(&self) -> &str {
        &self.fingerprint
    }

    /// Returns the certificate's serial number as the authority issued it.
    pub fn serial(&self) -> &str {
        &self.serial
    }

    /// Returns the shortest thing that still identifies this peer to a human.
    ///
    /// The common name when there is one, the whole subject when there is not, and the fingerprint
    /// when the subject is empty — which is legal, and is what a certificate that identifies itself
    /// only by its SANs looks like.
    pub fn label(&self) -> &str {
        self.common_name
            .as_deref()
            .filter(|name| !name.is_empty())
            .or(Some(self.subject.as_str()))
            .filter(|subject| !subject.is_empty())
            .unwrap_or(&self.fingerprint)
    }

    /// Reports whether any entry in `allowed` names this peer.
    ///
    /// An empty list matches nothing. That is the only safe reading of "nobody is on the list", and
    /// the caller decides separately whether an empty list is a configuration it will start with.
    pub fn is_allowed_by(&self, allowed: &[AllowedPeer]) -> bool {
        allowed.iter().any(|entry| entry.matches(self))
    }
}

impl fmt::Display for PeerIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.label())
    }
}

/// One entry of the list of peers a surface answers.
///
/// Written as `cn:name`, `dn:CN=name,O=org` or `sha256:<hex>`. A bare value is read as a common
/// name, because that is what it always turns out to be and refusing it would only cost a round trip
/// through the documentation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AllowedPeer {
    /// Matches any certificate whose common name is exactly this.
    CommonName(String),
    /// Matches any certificate whose whole subject is exactly this.
    Subject(String),
    /// Matches exactly one certificate, and stops matching when it is renewed.
    Fingerprint(String),
}

impl AllowedPeer {
    /// Reports whether this entry names `peer`.
    pub fn matches(&self, peer: &PeerIdentity) -> bool {
        match self {
            Self::CommonName(name) => peer.common_name() == Some(name.as_str()),
            Self::Subject(subject) => peer.subject() == subject,
            // Hex, so case is not meaningful and an entry pasted from a tool that upper-cases it is
            // the same entry.
            Self::Fingerprint(fingerprint) => peer.fingerprint().eq_ignore_ascii_case(fingerprint),
        }
    }

    /// Returns how this entry is written.
    pub fn kind(&self) -> &'static str {
        match self {
            Self::CommonName(_) => "cn",
            Self::Subject(_) => "dn",
            Self::Fingerprint(_) => "sha256",
        }
    }
}

impl FromStr for AllowedPeer {
    type Err = anyhow::Error;

    fn from_str(value: &str) -> Result<Self> {
        let value = value.trim();

        if value.is_empty() {
            bail!("an empty entry names no peer");
        }

        if let Some(name) = value.strip_prefix("cn:") {
            return non_empty(name).map(Self::CommonName);
        }

        if let Some(subject) = value.strip_prefix("dn:") {
            return non_empty(subject).map(Self::Subject);
        }

        if let Some(fingerprint) = value.strip_prefix("sha256:") {
            let fingerprint = fingerprint.trim().replace(':', "");

            if fingerprint.len() != 64 || !fingerprint.chars().all(|c| c.is_ascii_hexdigit()) {
                bail!(
                    "`{fingerprint}` is not a SHA-256 fingerprint: expected 64 hexadecimal \
                     characters"
                );
            }

            return Ok(Self::Fingerprint(fingerprint.to_ascii_lowercase()));
        }

        Ok(Self::CommonName(value.to_owned()))
    }
}

impl fmt::Display for AllowedPeer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CommonName(name) => write!(formatter, "cn:{name}"),
            Self::Subject(subject) => write!(formatter, "dn:{subject}"),
            Self::Fingerprint(fingerprint) => write!(formatter, "sha256:{fingerprint}"),
        }
    }
}

/// Rejects the entry that names nothing at all.
fn non_empty(value: &str) -> Result<String> {
    let value = value.trim();

    if value.is_empty() {
        bail!("an empty entry names no peer");
    }

    Ok(value.to_owned())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;

    const FINGERPRINT: &str = "3f9a0c2e5b71d84a6c0f1e2d3a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d";

    fn operator() -> PeerIdentity {
        PeerIdentity::new(
            "CN=local-operator,O=Permguard",
            Some("local-operator".to_owned()),
            FINGERPRINT,
            "01",
        )
    }

    #[test]
    fn test_a_bare_entry_is_read_as_a_common_name() {
        assert_eq!(
            "local-operator".parse::<AllowedPeer>().expect("it parses"),
            AllowedPeer::CommonName("local-operator".to_owned())
        );
    }

    #[test]
    fn test_every_written_form_round_trips() {
        for written in [
            "cn:local-operator",
            "dn:CN=local-operator,O=Permguard",
            &format!("sha256:{FINGERPRINT}"),
        ] {
            let parsed: AllowedPeer = written.parse().expect("it parses");

            assert_eq!(parsed.to_string(), written, "reading {written}");
        }
    }

    #[test]
    fn test_a_fingerprint_pasted_from_a_tool_is_the_same_entry() {
        // `openssl x509 -fingerprint` prints upper case, separated by colons.
        let pasted = FINGERPRINT
            .to_uppercase()
            .as_bytes()
            .chunks(2)
            .map(|pair| String::from_utf8_lossy(pair).into_owned())
            .collect::<Vec<_>>()
            .join(":");

        let entry: AllowedPeer = format!("sha256:{pasted}").parse().expect("it parses");

        assert!(entry.matches(&operator()));
    }

    #[test]
    fn test_a_fingerprint_that_is_not_one_says_so() {
        let error = "sha256:abcd"
            .parse::<AllowedPeer>()
            .expect_err("four characters is not a digest");

        assert!(format!("{error}").contains("64 hexadecimal"));
    }

    #[test]
    fn test_a_name_matches_the_name_and_nothing_near_it() {
        let allowed = [AllowedPeer::CommonName("local-operator".to_owned())];

        assert!(operator().is_allowed_by(&allowed));

        let other = PeerIdentity::new(
            "CN=local-operator-2",
            Some("local-operator-2".into()),
            "",
            "",
        );
        assert!(!other.is_allowed_by(&allowed));
    }

    #[test]
    fn test_an_empty_list_matches_nobody() {
        assert!(!operator().is_allowed_by(&[]));
    }

    #[test]
    fn test_a_subject_entry_does_not_match_a_common_name_entry() {
        let by_subject = [AllowedPeer::Subject(
            "CN=local-operator,O=Permguard".to_owned(),
        )];
        let by_name = [AllowedPeer::Subject("local-operator".to_owned())];

        assert!(operator().is_allowed_by(&by_subject));
        assert!(!operator().is_allowed_by(&by_name));
    }

    #[test]
    fn test_a_peer_falls_back_to_something_a_human_can_read() {
        assert_eq!(operator().label(), "local-operator");

        let no_name = PeerIdentity::new("O=Permguard", None, FINGERPRINT, "01");
        assert_eq!(no_name.label(), "O=Permguard");

        let nothing = PeerIdentity::new("", None, FINGERPRINT, "01");
        assert_eq!(nothing.label(), FINGERPRINT);
    }
}
