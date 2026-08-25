// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! Creates the material a deployment was not given — when, and only when, it is allowed to.
//!
//! # Why this is off by default
//!
//! A server that can mint its own certificate authority is a server whose trust nobody vouched for.
//! In production that is never what you want: certificates come from a real authority, keys come from
//! a real store, and a process that quietly generated its own would be trusted by nothing and would
//! not say so.
//!
//! In development it is exactly what you want: start the thing and have it work.
//!
//! Both are served by one rule — **the server generates only what `autogenerate` says it may, and
//! only what is actually missing**. Anything supplied is used untouched, anything missing without
//! permission stops the start with a message that says which file and how to provide it.
//!
//! # What it makes
//!
//! Under the working directory, in the shape a container would have mounted:
//!
//! ```text
//! .volume/
//! ├── data/                                 what the server keeps
//! ├── operations/                           the record-keeping subsystem, backed up as one unit
//! │   ├── state/                            what the server remembers about its own configuration
//! │   ├── audit/                            the trail, when it is kept here rather than in the log
//! │   ├── keys/                             the ring that seals the trail, which maintains itself
//! │   ├── secrets/audit-pseudonym           32 random bytes
//! │   └── secrets/decision-commitment       32 random bytes, when decisions are recorded
//! ├── tls/ca.{pem,key}                      a local authority
//! ├── tls/ca.crl                            its revocation list, revoking nothing yet
//! ├── tls/server.{pem,key}                  for localhost, signed by it
//! └── tls/client.{pem,key}                  what an operator presents to the administrative surface
//! ```
//!
//! A realm hosts the same `operations/` subsystem under `realms/<name>/operations/`, and — when it
//! issues tokens — its own signing keys at `realms/<name>/keys`.
//!
//! The directories exist whatever `autogenerate` says — a server that cannot write its own state
//! directory cannot run, and creating a directory grants no trust. Only the *material* inside
//! `secrets/` and `tls/` is generated, and only when it is allowed.
//!
//! Everything it writes is `0600`, in directories that are `0700`. Nothing is ever overwritten: a
//! file that exists is a file somebody meant to put there.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use ring::rand::{SecureRandom, SystemRandom};
use tracing::{info, warn};

use permguard_core::{AuditDestination, Config, SecretProvider};

/// The `component` every record of provisioning carries.
const COMPONENT: &str = "provision";

/// How many bytes of key material a generated secret gets.
const SECRET_BYTES: usize = 32;

/// How long a generated certificate is valid.
///
/// A year: long enough not to interrupt development, short enough that one which escaped into
/// something real expires rather than lingering.
const CERTIFICATE_DAYS: i64 = 365;

/// What a run needs, and where it lives.
#[derive(Debug, Clone)]
pub struct Volume {
    root: PathBuf,
}

impl Volume {
    /// Describes the volume the effective configuration points at.
    ///
    /// The volume *is* the working directory. There is nothing to derive.
    pub fn of(config: &Config) -> Self {
        Self {
            root: config.working_dir().to_path_buf(),
        }
    }

    /// Returns the directory the volume lives in.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Returns where secrets live, which is wherever the configuration resolved them to.
    pub fn secrets(&self, config: &Config) -> PathBuf {
        config.secrets_directory()
    }

    /// Returns where transport material lives.
    pub fn tls(&self) -> PathBuf {
        self.root.join("tls")
    }

    /// Returns where the server writes what it keeps.
    pub fn data(&self) -> PathBuf {
        self.root.join("data")
    }

    /// Returns the server's operations directory: the record-keeping subsystem, in one place.
    ///
    /// Its keys, secret, trail and state all live under here, so the whole thing backs up as a unit.
    pub fn operations(&self) -> PathBuf {
        self.root.join("operations")
    }

    /// Returns where the server remembers things about its own configuration.
    pub fn state(&self) -> PathBuf {
        self.operations().join("state")
    }

    /// Returns where the audit trail is kept, which is wherever the configuration resolved it to.
    pub fn audit(&self, config: &Config) -> PathBuf {
        config.audit_directory()
    }

    /// Returns where the signing key ring lives, which is wherever the configuration resolved it to.
    pub fn keys(&self, config: &Config) -> PathBuf {
        config.keys_directory()
    }
}

/// Creates whatever the configuration needs and does not have.
///
/// Called before the configuration is validated, so that validation sees the finished picture and
/// reports what is still missing in the same terms whether it was generated or supplied.
pub fn prepare(config: &Config) -> Result<()> {
    let volume = Volume::of(config);

    // The volume exists whatever else happens: it is where the server keeps what it keeps, and one
    // that cannot write its own state directory cannot run. Creating a directory grants no trust —
    // that is what `autogenerate` decides, below.
    create_directory(volume.root())
        .with_context(|| format!("preparing the volume at {}", volume.root().display()))?;

    // `operations/` is created before its children so the container that holds the trail, the keys
    // that seal it and the pseudonymisation secret is itself `0700`, not left at the umask default.
    for directory in [volume.data(), volume.operations(), volume.state()] {
        create_directory(&directory)?;
    }

    if config.keys_enabled() {
        create_directory(&volume.keys(config))?;
    }

    if config.audit_destination() == AuditDestination::File {
        create_directory(&volume.audit(config))?;
    }

    if !config.autogenerate() {
        // Nothing further: a deployment that supplies its own material is the normal case, and
        // validation is about to report anything that is actually missing.
        return Ok(());
    }

    warn!(
        event.name = "provision.enabled",
        component = COMPONENT,
        volume = %volume.root().display(),
        "generating missing material: this build trusts material it made itself, which is never \
         appropriate outside development"
    );

    for directory in [volume.secrets(config), volume.tls()] {
        create_directory(&directory)?;
    }

    prepare_secrets(config, &volume)?;
    prepare_certificates(config, &volume)?;

    Ok(())
}

/// Writes the secrets the configuration names and the store does not have.
///
/// The server's, and then one per realm in the realm's own secrets directory — a *distinct* key, so
/// the same subject pseudonymised in two realms cannot be recognised as the same subject across them.
/// That per-tenant key is the whole privacy point of a realm having its own secret rather than sharing.
fn prepare_secrets(config: &Config, volume: &Volume) -> Result<()> {
    // The server's own key, when the server pseudonymises.
    if config.audit_pseudonym_enabled()
        && let Some(reference) = config.audit_pseudonym_key_ref()
    {
        generate_secret(
            &volume.secrets(config).join(reference.name()),
            reference.name(),
        )?;
    }

    // The key input commitments are taken under, when this plane records decisions. A *different*
    // secret from the pseudonymisation one, and deliberately: they protect different things, and
    // rotating one to crypto-shred pseudonyms must not silently invalidate every commitment too.
    if config.log_enabled()
        && let Some(reference) = config.log_commitment_key_ref()
    {
        generate_secret(
            &volume.secrets(config).join(reference.name()),
            reference.name(),
        )?;
    }

    // Each realm that pseudonymises from a directory gets its own key, and only those: a realm with
    // pseudonymisation off, or resolving its secrets from the environment, has nothing to generate.
    // A realm can enable it even when the server did not, so it is decided per realm.
    for realm in config.realms() {
        if !realm.audit_pseudonym_enabled() || realm.secrets_provider() != SecretProvider::Directory
        {
            continue;
        }

        let Some(reference) = realm.audit_pseudonym_key_ref() else {
            continue;
        };

        let directory = config.realm_secrets_directory(realm.name());
        create_directory(&directory)?;
        generate_secret(&directory.join(reference.name()), reference.name())?;
    }

    Ok(())
}

/// Writes `SECRET_BYTES` of random material to `path`, unless something is already there.
///
/// Never overwrites: a file that exists is one somebody meant to put there, and regenerating a
/// pseudonymisation key silently would break every pseudonym written under the old one.
fn generate_secret(path: &Path, reference: &str) -> Result<()> {
    if path.exists() {
        return Ok(());
    }

    // The same generator `rustls` and the key ring already use. Drawing this from a second
    // random-number implementation would mean two of them to review, two to keep patched, and two
    // chances for a platform to be supported by one and not the other — for thirty-two bytes.
    let mut material = [0_u8; SECRET_BYTES];
    SystemRandom::new()
        .fill(&mut material)
        .map_err(|_| anyhow::anyhow!("the system random number generator refused"))
        .context("drawing random bytes for a generated secret")?;

    write_private(path, hex(&material).as_bytes())?;

    info!(
        event.name = "provision.secret",
        component = COMPONENT,
        secret.reference = reference,
        path = %path.display(),
        "generated a secret"
    );

    Ok(())
}

/// Writes the certificates the configuration names and does not have.
///
/// Either every piece is generated together or none is: a server certificate signed by an authority
/// that has since been regenerated verifies against nothing, and half a set is worse than none.
fn prepare_certificates(config: &Config, volume: &Volume) -> Result<()> {
    let wanted = [
        config.public_tls(),
        config.admin_tls(),
        config.telemetry_tls(),
    ];

    if wanted.iter().all(Option::is_none) {
        return Ok(());
    }

    let tls = volume.tls();
    let authority = (tls.join("ca.pem"), tls.join("ca.key"));
    let server = (tls.join("server.pem"), tls.join("server.key"));
    let client = (tls.join("client.pem"), tls.join("client.key"));
    let revocations = tls.join("ca.crl");

    let present = [&authority, &server, &client]
        .iter()
        .filter(|(certificate, key)| certificate.exists() && key.exists())
        .count();

    if present == 3 {
        return Ok(());
    }

    if present > 0 {
        bail!(
            "the generated certificates under {} are incomplete: remove them and start again, \
             because a server certificate signed by an authority that is no longer there verifies \
             against nothing",
            tls.display()
        );
    }

    issue(&authority, &server, &client, &revocations)?;

    info!(
        event.name = "provision.certificates",
        component = COMPONENT,
        path = %tls.display(),
        days = CERTIFICATE_DAYS,
            "generated a local authority, its revocation list, a server certificate for localhost, and \
         a client certificate"
    );

    Ok(())
}

/// Issues the authority and the two certificates it signs.
fn issue(
    authority: &(PathBuf, PathBuf),
    server: &(PathBuf, PathBuf),
    client: &(PathBuf, PathBuf),
    revocations: &Path,
) -> Result<()> {
    let mut authority_params = rcgen::CertificateParams::new(Vec::new())
        .context("describing the local certificate authority")?;
    authority_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    authority_params.distinguished_name.push(
        rcgen::DnType::CommonName,
        "permguard local development authority",
    );

    let authority_key = rcgen::KeyPair::generate().context("generating the authority key")?;
    let authority_certificate = authority_params
        .self_signed(&authority_key)
        .context("signing the authority certificate")?;
    let issuer = rcgen::Issuer::from_params(&authority_params, &authority_key);

    write_public(&authority.0, authority_certificate.pem().as_bytes())?;
    write_private(&authority.1, authority_key.serialize_pem().as_bytes())?;

    // The server certificate has to name both spellings of localhost, because a client that dials
    // 127.0.0.1 and one that dials `localhost` are checking different things.
    let mut server_params = rcgen::CertificateParams::new(vec!["localhost".to_owned()])
        .context("describing the server certificate")?;
    server_params
        .subject_alt_names
        .push(rcgen::SanType::IpAddress(std::net::IpAddr::from([
            127, 0, 0, 1,
        ])));
    server_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "localhost");
    let server_key = rcgen::KeyPair::generate().context("generating the server key")?;
    let server_certificate = server_params
        .signed_by(&server_key, &issuer)
        .context("signing the server certificate")?;

    write_public(&server.0, server_certificate.pem().as_bytes())?;
    write_private(&server.1, server_key.serialize_pem().as_bytes())?;

    let mut client_params =
        rcgen::CertificateParams::new(Vec::new()).context("describing the client certificate")?;
    client_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "local-operator");
    let client_key = rcgen::KeyPair::generate().context("generating the client key")?;
    let client_certificate = client_params
        .signed_by(&client_key, &issuer)
        .context("signing the client certificate")?;

    write_public(&client.0, client_certificate.pem().as_bytes())?;
    write_private(&client.1, client_key.serialize_pem().as_bytes())?;

    write_public(revocations, &empty_revocation_list(&issuer)?)?;

    Ok(())
}

/// Issues a revocation list that revokes nothing.
///
/// It exists so that the revocation path can be configured, and therefore exercised, without an
/// operator first having to learn how to produce a list by hand. A list that revokes nothing and no
/// list at all are opposite things to a listener — one means "checked, and this client is fine", the
/// other means "not checked" — and only the first is worth being able to try locally.
///
/// The validity window is deliberately wide and is not a security property here: this material is
/// development material, replaced whenever the authority beside it is, and `rustls` does not enforce
/// a list's validity period in any case.
fn empty_revocation_list(issuer: &rcgen::Issuer<'_, &rcgen::KeyPair>) -> Result<Vec<u8>> {
    let params = rcgen::CertificateRevocationListParams {
        this_update: rcgen::date_time_ymd(2000, 1, 1),
        next_update: rcgen::date_time_ymd(9999, 1, 1),
        crl_number: rcgen::SerialNumber::from(1_u64),
        issuing_distribution_point: None,
        revoked_certs: Vec::new(),
        key_identifier_method: rcgen::KeyIdMethod::Sha256,
    };

    let list = params
        .signed_by(issuer)
        .context("signing the revocation list")?;

    Ok(list
        .pem()
        .context("writing the revocation list")?
        .into_bytes())
}

/// Creates a directory nobody else can enter.
fn create_directory(path: &Path) -> Result<()> {
    fs::create_dir_all(path).with_context(|| format!("creating {}", path.display()))?;
    restrict(path, 0o700)
}

/// Writes material only this user may read.
fn write_private(path: &Path, contents: &[u8]) -> Result<()> {
    fs::write(path, contents).with_context(|| format!("writing {}", path.display()))?;
    restrict(path, 0o600)
}

/// Writes material that is meant to be readable — a certificate is public by definition.
fn write_public(path: &Path, contents: &[u8]) -> Result<()> {
    fs::write(path, contents).with_context(|| format!("writing {}", path.display()))
}

/// Narrows permissions where the platform has them.
#[cfg(unix)]
fn restrict(path: &Path, mode: u32) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    fs::set_permissions(path, fs::Permissions::from_mode(mode))
        .with_context(|| format!("restricting {}", path.display()))
}

#[cfg(not(unix))]
fn restrict(_path: &Path, _mode: u32) -> Result<()> {
    Ok(())
}

/// Renders bytes as hexadecimal, which is what a key in a file looks like everywhere else.
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hex_is_two_characters_per_byte() {
        assert_eq!(hex(&[0x00, 0x0f, 0xff]), "000fff");
        assert_eq!(hex(&[0_u8; SECRET_BYTES]).len(), SECRET_BYTES * 2);
    }
}
