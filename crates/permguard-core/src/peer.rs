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
    /// The URI subject alternative names, in certificate order: what an authorization principal
    /// is read from (WP-2.4); the subject and common name above are labels.
    san_uris: Vec<String>,
    /// The SHA-256 of the subject public key info, lowercase hex: the other identifier a mapper
    /// rule may pin, surviving a renewal that keeps the key.
    spki_sha256: Option<String>,
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
            san_uris: Vec::new(),
            spki_sha256: None,
        }
    }

    /// Adds the URI subject alternative names the certificate carries.
    pub fn with_san_uris(mut self, uris: Vec<String>) -> Self {
        self.san_uris = uris;
        self
    }

    /// Adds the SHA-256 of the certificate's subject public key info, lowercase hex.
    pub fn with_spki_sha256(mut self, digest: impl Into<String>) -> Self {
        self.spki_sha256 = Some(digest.into());
        self
    }

    /// The URI subject alternative names, in certificate order.
    pub fn san_uris(&self) -> &[String] {
        &self.san_uris
    }

    /// The SHA-256 of the subject public key info, when the acceptor computed it.
    pub fn spki_sha256(&self) -> Option<&str> {
        self.spki_sha256.as_deref()
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

/// The RFC 9266 `tls-exporter` channel binding of one TLS 1.3 connection (WP-2.3):
/// `TLS-Exporter("EXPORTER-Channel-Binding", "", 32)`, computed by whatever terminated that
/// connection and handed to every request on it. A peer Host session signs it, so a proof made on
/// one connection never verifies on another; it is never read from a request, a header or a
/// frame, which is what makes a forwarded value no substitute.
///
/// One proof exchange authenticates one connection: the first session [`ChannelBinding::claim`]s
/// the binding, and every request of the connection shares that claim.
#[derive(Clone)]
pub struct ChannelBinding {
    exporter: [u8; 32],
    claimed: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

impl ChannelBinding {
    /// The binding of a connection whose exporter is `exporter`, not yet claimed.
    pub fn new(exporter: [u8; 32]) -> Self {
        Self {
            exporter,
            claimed: std::sync::Arc::default(),
        }
    }

    /// The exporter value.
    pub fn exporter(&self) -> &[u8; 32] {
        &self.exporter
    }

    /// Claims the binding for one proof exchange: `true` the first time on this connection,
    /// `false` ever after.
    pub fn claim(&self) -> bool {
        !self.claimed.swap(true, std::sync::atomic::Ordering::SeqCst)
    }
}

impl PartialEq for ChannelBinding {
    fn eq(&self, other: &Self) -> bool {
        self.exporter == other.exporter
    }
}

impl Eq for ChannelBinding {}

impl fmt::Debug for ChannelBinding {
    /// Keyed by the connection's secrets: never written out.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ChannelBinding(..)")
    }
}

/// One `host.peers[]` entry (WP-2.3): a peer Host this one opens sessions with, by its `host_id`
/// and its first identity fingerprint, pinned out of band. Written `<host_id> sha256:<hex>`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PinnedPeer {
    host_id: [u8; 16],
    fingerprint: String,
}

impl PinnedPeer {
    /// The peer's `host_id`.
    pub fn host_id(&self) -> [u8; 16] {
        self.host_id
    }

    /// The peer's first identity fingerprint, `sha256:<hex>`.
    pub fn fingerprint(&self) -> &str {
        &self.fingerprint
    }
}

impl FromStr for PinnedPeer {
    type Err = anyhow::Error;

    fn from_str(value: &str) -> Result<Self> {
        let Some((host_id, fingerprint)) = value.trim().split_once(char::is_whitespace) else {
            bail!("a pinned peer is `<host_id> sha256:<hex>`");
        };
        let hex: String = host_id.chars().filter(|c| *c != '-').collect();
        let canonical = host_id.len() == 36
            && [8, 13, 18, 23]
                .iter()
                .all(|at| host_id.as_bytes().get(*at) == Some(&b'-'))
            && hex.len() == 32
            && hex
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase());
        let mut bytes = [0u8; 16];
        for (at, byte) in bytes.iter_mut().enumerate() {
            *byte = canonical
                .then(|| u8::from_str_radix(hex.get(at * 2..at * 2 + 2)?, 16).ok())
                .flatten()
                .unwrap_or_default();
        }
        // A UUIDv7: version 7, the RFC 9562 variant.
        if !canonical || bytes[6] >> 4 != 7 || bytes[8] >> 6 != 0b10 {
            bail!("`{host_id}` is not a Host id: a lowercase UUIDv7");
        }
        let fingerprint = fingerprint.trim();
        let digest = fingerprint.strip_prefix("sha256:").unwrap_or_default();
        if digest.len() != 64
            || !digest
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        {
            bail!(
                "`{fingerprint}` is not an identity fingerprint: `sha256:` and 64 lowercase hex \
                 characters"
            );
        }
        Ok(Self {
            host_id: bytes,
            fingerprint: fingerprint.to_owned(),
        })
    }
}

impl fmt::Display for PinnedPeer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let hex: String = self.host_id.iter().map(|b| format!("{b:02x}")).collect();
        write!(
            formatter,
            "{}-{}-{}-{}-{} {}",
            &hex[..8],
            &hex[8..12],
            &hex[12..16],
            &hex[16..20],
            &hex[20..],
            self.fingerprint
        )
    }
}

/// Whether the Host listener serves peer Host sessions, as the deployment states it with
/// `admin.peer_sessions` (WP-2.3). A TLS-terminating proxy or sidecar is invisible to the
/// process, so a deployment behind one says `disabled`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerSessions {
    /// The listener's TLS connections are end to end with the peers.
    EndToEnd,
    /// Peer sessions are not served.
    Disabled,
}

impl PeerSessions {
    /// The word the setting is written as.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::EndToEnd => "end_to_end",
            Self::Disabled => "disabled",
        }
    }
}

impl FromStr for PeerSessions {
    type Err = anyhow::Error;

    fn from_str(value: &str) -> Result<Self> {
        match value.trim() {
            "end_to_end" => Ok(Self::EndToEnd),
            "disabled" => Ok(Self::Disabled),
            other => bail!("`{other}` is not a peer-session mode: `end_to_end` or `disabled`"),
        }
    }
}

/// What discovery publishes about peer sessions: whether they are served and, when they are not
/// or are with a limit, why (WP-2.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub struct PeerSessionsReport {
    /// Whether the PeerChannel serves sessions on this listener.
    pub served: bool,
    /// Why not, or the limit it serves them under.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<&'static str>,
}

impl PeerSessionsReport {
    /// No Host listener is configured.
    pub const NO_LISTENER: &'static str = "no_listener";
    /// `admin.peer_sessions` is `disabled`.
    pub const DISABLED: &'static str = "disabled";
    /// The listener demands no client certificate.
    pub const NO_CLIENT_CERTIFICATE: &'static str = "no_client_certificate";
    /// Served, and a connection the listener accepts at TLS 1.2 is refused a session: the
    /// RFC 9266 exporter is used only on TLS 1.3.
    pub const TLS_1_2_REFUSED: &'static str = "tls_1_2_refused";
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
