// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The command line as a service account (`2-security/7` The client): its access key and secret
//! key, from the flags or the configuration, obtain a token at the Authority Plane's token
//! endpoint; every command that reaches a Plane or a Host API sends it when no `--token-file` is
//! given. The token is kept under `~/.permguard/tokens/`, in a file only its owner reads, keyed by
//! the access key, whether flagged, configured or named by the key file, its secret key, the
//! Authority Plane and what it asked for, and reused until a minute before it expires. Nothing here traces a secret or a token: the trace names the access key and the expiry.

use std::path::{Path, PathBuf};

use permguard_control_client::tls::{Credential, TlsOptions};
use permguard_control_client::token_source::{Issued, REFRESH_AHEAD, TokenSource};
use zeroize::Zeroizing;

use crate::args::Globals;
use crate::failure::Failure;
use crate::settings::Store;
use crate::trace::Trace;

/// The most a secret or cache file may hold.
const FILE_MAX: u64 = 64 * 1024;

/// The access key the flags or the configuration name.
fn access_key(globals: &Globals, store: &Store) -> Option<String> {
    globals
        .access_key
        .clone()
        .or_else(|| {
            crate::target::setting_value("auth.client.access_key", store).map(|(value, _)| value)
        })
        .map(|key| key.trim().to_owned())
        .filter(|key| !key.is_empty())
}

/// Where the Authority Plane is: `--authority-endpoint` or `auth.client.authority_endpoint`.
pub fn authority_endpoint(globals: &Globals, store: &Store) -> Option<String> {
    globals.authority_endpoint.clone().or_else(|| {
        crate::target::setting_value("auth.client.authority_endpoint", store)
            .map(|(value, _)| value)
    })
}

/// The scope a command's token asks: `PERMGUARD_CLIENT_SCOPE` or `auth.client.scope`, comma or
/// space separated; the account's whole when unset.
fn scope(store: &Store) -> Option<String> {
    crate::target::setting_value("auth.client.scope", store)
        .map(|(value, _)| value.replace(',', " "))
        .filter(|scope| !scope.trim().is_empty())
}

/// The Authority Plane's own connection: never a Plane's server name, its own authority when one
/// is stated, and never a bearer.
pub fn authority_tls(
    globals: &Globals,
    store: &Store,
    trace: &Trace,
) -> Result<TlsOptions, Failure> {
    let mut tls = crate::target::base_tls(globals, store, trace)?;
    tls.server_name = None;
    tls.token = None;
    let authority = match &globals.authority_tls_ca_file {
        Some(flag) if flag.is_absolute() => Some(flag.clone()),
        Some(flag) => Some(globals.workdir.join(flag)),
        None => crate::target::configured("auth.client.tls_ca_file", store, globals),
    };
    if let Some(authority) = authority {
        tls.ca_file = Some(authority);
    }
    Ok(tls)
}

/// The secret key a file holds: the `secret_key:` line of a key file the Authority Plane wrote,
/// or the whole file.
pub fn secret_of(text: &str) -> Option<Zeroizing<String>> {
    text.lines()
        .find_map(|line| line.trim().strip_prefix("secret_key:"))
        .map(|secret| secret.trim().to_owned())
        .or_else(|| Some(text.trim().to_owned()))
        .filter(|secret| secret.starts_with("pgsk_"))
        .map(Zeroizing::new)
}

/// The access key a key file names, when it names one.
pub fn access_key_of(text: &str) -> Option<String> {
    text.lines()
        .find_map(|line| line.trim().strip_prefix("access_key:"))
        .map(|key| key.trim().to_owned())
        .filter(|key| key.starts_with("pgak_"))
}

/// The client the flags or the configuration name, when there is one: its access key and its
/// secret key. A key file names its access key itself, so `--secret-key-file` alone is enough.
pub fn credentials(
    globals: &Globals,
    store: &Store,
) -> Result<Option<(String, Zeroizing<String>)>, Failure> {
    let secret_file = match &globals.secret_key_file {
        Some(flag) if flag.is_absolute() => Some(flag.clone()),
        Some(flag) => Some(globals.workdir.join(flag)),
        None => crate::target::configured("auth.client.secret_file", store, globals),
    };
    let named = access_key(globals, store);
    if named.is_none() && secret_file.is_none() {
        return Ok(None);
    }
    let secret_file = secret_file.ok_or_else(|| {
        Failure::usage(
            "the client's secret key is read from a file only its owner reads: \
             --secret-key-file or auth.client.secret_file",
        )
    })?;
    let held = read_secret_file(&secret_file)?;
    let text = Zeroizing::new(
        String::from_utf8(held.expose().to_vec())
            .map_err(|_| Failure::usage("the secret key file is not text"))?,
    );
    let secret = secret_of(&text).ok_or_else(|| {
        Failure::usage(format!(
            "{} holds no secret key: a `secret_key: pgsk_…` line, or the key alone",
            secret_file.display()
        ))
    })?;
    let access_key = named.or_else(|| access_key_of(&text)).ok_or_else(|| {
        Failure::usage("the client names its access key: --access-key or auth.client.access_key")
    })?;
    Ok(Some((access_key, secret)))
}

/// The client the flags or the configuration name, when there is one: its token source, and where
/// its token is kept.
fn source(
    globals: &Globals,
    store: &Store,
    trace: &Trace,
) -> Result<Option<(TokenSource, Option<PathBuf>)>, Failure> {
    let Some((access_key, secret)) = credentials(globals, store)? else {
        return Ok(None);
    };
    let endpoint = authority_endpoint(globals, store).ok_or_else(|| {
        Failure::usage(
            "the client obtains its tokens at the Authority Plane: --authority-endpoint or \
             auth.client.authority_endpoint",
        )
    })?;
    let tls = authority_tls(globals, store, trace)?;
    trace.say(format!(
        "the access key {access_key} obtains its tokens at {endpoint}"
    ));
    let scope = scope(store);
    let cache = cache_path(&access_key, &secret, &endpoint, scope.as_deref());
    TokenSource::new(&endpoint, &access_key, secret, scope, tls)
        .map(|source| Some((source, cache)))
        .map_err(|failure| Failure::from_client(&failure))
}

/// Whether this run sent the configured client's token, so a refusal of it drops the kept copy.
static SENT: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// The configured client's token, from the cache while it serves, else obtained now: `None`
/// without a client.
pub fn token(
    globals: &Globals,
    store: &Store,
    trace: &Trace,
) -> Result<Option<Credential>, Failure> {
    let Some((source, cache)) = source(globals, store, trace)? else {
        return Ok(None);
    };
    if let Some(held) = cache.as_deref().and_then(read_cached) {
        source.hold(held);
    }
    let issued = source
        .token()
        .map_err(|failure| Failure::from_client(&failure))?;
    if let Some(cache) = &cache {
        write_cached(cache, &issued);
    }
    trace.say(format!(
        "acting with the client's token, valid until {}",
        permguard_core::time::to_rfc3339(i64::try_from(issued.expires_at).unwrap_or(i64::MAX))
    ));
    SENT.store(true, std::sync::atomic::Ordering::Relaxed);
    Ok(Some(issued.token))
}

/// After a command failed: when a surface refused the client's token this run sent, revoked,
/// suspended or expired, the kept copy is dropped, and the next command obtains another rather
/// than sending it again.
pub fn forget_refused(globals: &Globals, code: &str) {
    if code != permguard_core::codes::common::UNAUTHENTICATED
        || !SENT.load(std::sync::atomic::Ordering::Relaxed)
    {
        return;
    }
    if let Ok(store) = crate::session::open_store(globals, &Trace::new(false)) {
        forget(globals, &store);
    }
}

/// The client's kept token, while it has not expired, and where it is kept: `None` without a
/// client or a kept token.
pub fn kept(globals: &Globals, store: &Store) -> Result<Option<(Issued, PathBuf)>, Failure> {
    let Some(path) = client_cache(globals, store)? else {
        return Ok(None);
    };
    Ok(read_kept(&path, 0).map(|issued| (issued, path)))
}

/// Where the configured client's token is kept: `None` without a client or a home directory.
pub fn client_cache(globals: &Globals, store: &Store) -> Result<Option<PathBuf>, Failure> {
    let Some((access_key, secret)) = credentials(globals, store)? else {
        return Ok(None);
    };
    let endpoint = authority_endpoint(globals, store).ok_or_else(|| {
        Failure::usage(
            "the client obtains its tokens at the Authority Plane: --authority-endpoint or \
             auth.client.authority_endpoint",
        )
    })?;
    Ok(cache_path(
        &access_key,
        &secret,
        &endpoint,
        scope(store).as_deref(),
    ))
}

/// Drops the token kept for the configured client: a surface refused it, revoked or suspended,
/// and the next command obtains another rather than sending it again.
pub fn forget(globals: &Globals, store: &Store) {
    if let Ok(Some(path)) = client_cache(globals, store) {
        let _ = std::fs::remove_file(path);
    }
}

/// The name a client's token is kept under: which access key, where and for what, keyed by its
/// secret key, so another key file, or the same access key with another secret, never reads it.
/// An HMAC, so the name says nothing of the secret.
fn cache_name(access_key: &str, secret: &str, endpoint: &str, scope: Option<&str>) -> String {
    let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, secret.as_bytes());
    let named = format!("{access_key}\n{endpoint}\n{}", scope.unwrap_or_default());
    ring::hmac::sign(&key, named.as_bytes()).as_ref()[..16]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// Where the token for this client is kept: none without a home directory.
fn cache_path(
    access_key: &str,
    secret: &str,
    endpoint: &str,
    scope: Option<&str>,
) -> Option<PathBuf> {
    let home = crate::settings::home_directory().ok()?;
    Some(home.join(".permguard").join("tokens").join(format!(
        "{}.json",
        cache_name(access_key, secret, endpoint, scope)
    )))
}

/// A file only its owner reads, of at most [`FILE_MAX`] bytes: never a link or a FIFO, and the file
/// read is the file checked.
fn private_file(path: &Path, what: &str) -> Result<Credential, Failure> {
    use std::io::Read as _;

    let refused = |why: String| Failure::usage(format!("{what} {}: {why}", path.display()));
    let named = std::fs::symlink_metadata(path).map_err(|error| refused(error.to_string()))?;
    if !named.is_file() {
        return Err(refused("is not a regular file".to_owned()));
    }
    let file = std::fs::File::open(path).map_err(|error| refused(error.to_string()))?;
    let opened = file
        .metadata()
        .map_err(|error| refused(error.to_string()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        if (opened.dev(), opened.ino()) != (named.dev(), named.ino()) {
            return Err(refused("changed while it was read".to_owned()));
        }
        if opened.mode() & 0o077 != 0 {
            return Err(refused(
                "may be read by others than its owner: chmod 600 it".to_owned(),
            ));
        }
        if opened.uid() != rustix::process::getuid().as_raw() {
            return Err(refused("belongs to another user".to_owned()));
        }
    }
    if !opened.is_file() || opened.len() > FILE_MAX {
        return Err(refused("is not a file of at most 64 KiB".to_owned()));
    }
    let mut bytes = Vec::new();
    file.take(FILE_MAX + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| refused(error.to_string()))?;
    Ok(Credential::new(bytes))
}

/// Why a secret key file is refused, by its owner, its mode, the reader's user and whether the path
/// named a link; `None` when it is read. As PostgreSQL decides for its key files: the reader's own
/// file, which nobody else reads and which is named, not linked to; or a file root owns that its
/// group may only read, which is how an orchestrator mounts a secret for a process that is not
/// root (a Kubernetes Secret volume under `fsGroup`, reached through the volume's own links). Only
/// root places such a file, and what is read must still be a `pgsk_` secret.
fn secret_file_refusal(owner: u32, mode: u32, reader: u32, linked: bool) -> Option<&'static str> {
    if owner == reader {
        if linked {
            return Some("is a link: name the file itself");
        }
        if mode & 0o077 != 0 {
            return Some("may be read by others than its owner: chmod 600 it");
        }
        return None;
    }
    if owner == 0 {
        if mode & 0o037 != 0 {
            return Some(
                "is root's and may be written by its group or read by others: chmod 440 it",
            );
        }
        return None;
    }
    Some("belongs to another user")
}

/// The secret key file, read as [`secret_file_refusal`] allows: a regular file of at most
/// [`FILE_MAX`] bytes, the file read being the file checked.
fn read_secret_file(path: &Path) -> Result<Credential, Failure> {
    use std::io::Read as _;

    let refused =
        |why: String| Failure::usage(format!("the secret key file {}: {why}", path.display()));
    let named = std::fs::symlink_metadata(path).map_err(|error| refused(error.to_string()))?;
    let linked = named.file_type().is_symlink();
    if !linked && !named.is_file() {
        return Err(refused("is not a regular file".to_owned()));
    }
    let target = std::fs::metadata(path).map_err(|error| refused(error.to_string()))?;
    let file = std::fs::File::open(path).map_err(|error| refused(error.to_string()))?;
    let opened = file
        .metadata()
        .map_err(|error| refused(error.to_string()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        if (opened.dev(), opened.ino()) != (target.dev(), target.ino()) {
            return Err(refused("changed while it was read".to_owned()));
        }
        let reader = rustix::process::getuid().as_raw();
        if let Some(why) = secret_file_refusal(opened.uid(), opened.mode(), reader, linked) {
            return Err(refused(why.to_owned()));
        }
    }
    #[cfg(not(unix))]
    {
        let _ = target;
        if linked {
            return Err(refused("is a link: name the file itself".to_owned()));
        }
    }
    if !opened.is_file() || opened.len() > FILE_MAX {
        return Err(refused("is not a file of at most 64 KiB".to_owned()));
    }
    let mut bytes = Vec::new();
    file.take(FILE_MAX + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| refused(error.to_string()))?;
    Ok(Credential::new(bytes))
}

/// Whether `directory` is the user's own and only theirs: a cache anybody else could write or
/// read is not used.
fn private_directory(directory: &Path) -> bool {
    let Ok(held) = std::fs::symlink_metadata(directory) else {
        return false;
    };
    if !held.is_dir() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        held.uid() == rustix::process::getuid().as_raw() && held.mode() & 0o077 == 0
    }
    #[cfg(not(unix))]
    {
        true
    }
}

fn read_cached(path: &Path) -> Option<Issued> {
    read_kept(path, REFRESH_AHEAD.as_secs())
}

/// The token kept at `path` while more than `ahead` seconds of it remain.
fn read_kept(path: &Path, ahead: u64) -> Option<Issued> {
    if !path.parent().is_some_and(private_directory) {
        return None;
    }
    let held = private_file(path, "the token cache").ok()?;
    let value: serde_json::Value = serde_json::from_slice(held.expose()).ok()?;
    let token = value["token"].as_str()?;
    let expires_at = value["expires_at"].as_u64()?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs());
    (expires_at > now + ahead).then(|| Issued {
        token: Credential::new(token.as_bytes().to_vec()),
        expires_at,
    })
}

/// Keeps `issued` for the next command, in a directory and a file only their owner reads; a cache
/// that cannot be written costs the next command a request, never this one.
fn write_cached(path: &Path, issued: &Issued) {
    use std::io::Write as _;

    let Some(directory) = path.parent() else {
        return;
    };
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt as _;
        builder.mode(0o700);
    }
    if builder.create(directory).is_err() || !private_directory(directory) {
        return;
    }
    let Ok(token) = std::str::from_utf8(issued.token.expose()) else {
        return;
    };
    let body = serde_json::json!({"token": token, "expires_at": issued.expires_at}).to_string();
    let mut suffix = [0u8; 8];
    if ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut suffix).is_err() {
        return;
    }
    let aside = directory.join(format!(
        ".{}.part",
        suffix
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    ));
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let written = options
        .open(&aside)
        .and_then(|mut file| file.write_all(body.as_bytes()))
        .and_then(|()| std::fs::rename(&aside, path));
    if written.is_err() {
        let _ = std::fs::remove_file(&aside);
    }
}

#[cfg(test)]
mod tests {
    use super::{cache_name, read_secret_file, secret_file_refusal};

    const READER: u32 = 65532;

    /// The reader's own file: only its owner reads it, and it is named, never linked to.
    #[test]
    fn the_readers_own_secret_file_is_read_only_when_nobody_else_reads_it() {
        assert_eq!(secret_file_refusal(READER, 0o100600, READER, false), None);
        assert_eq!(secret_file_refusal(READER, 0o100400, READER, false), None);
        for mode in [0o100640, 0o100604, 0o100660, 0o100644] {
            assert!(
                secret_file_refusal(READER, mode, READER, false).is_some(),
                "{mode:o}"
            );
        }
        assert!(secret_file_refusal(READER, 0o100600, READER, true).is_some());
    }

    /// A file root owns, as an orchestrator mounts a secret: its group may read it, nobody may
    /// write it but root, and others may not read it, linked to or not.
    #[test]
    fn a_secret_file_root_mounts_may_be_read_by_its_group_alone() {
        for linked in [false, true] {
            assert_eq!(secret_file_refusal(0, 0o100440, READER, linked), None);
            assert_eq!(secret_file_refusal(0, 0o100400, READER, linked), None);
            assert_eq!(secret_file_refusal(0, 0o100640, READER, linked), None);
            for mode in [0o100444, 0o100460, 0o100644, 0o100470, 0o100441] {
                assert!(
                    secret_file_refusal(0, mode, READER, linked).is_some(),
                    "{mode:o} linked {linked}"
                );
            }
        }
    }

    /// Anybody else's file is never read, whatever its mode.
    #[test]
    fn a_secret_file_of_another_user_is_refused() {
        assert_eq!(
            secret_file_refusal(1000, 0o100400, READER, false),
            Some("belongs to another user")
        );
        assert!(secret_file_refusal(1000, 0o100440, READER, true).is_some());
    }

    /// Root reading its own file is held to the owner's rule: nobody else, and no link.
    #[test]
    fn root_reading_its_own_file_follows_the_owners_rule() {
        assert_eq!(secret_file_refusal(0, 0o100600, 0, false), None);
        assert!(secret_file_refusal(0, 0o100640, 0, false).is_some());
        assert!(secret_file_refusal(0, 0o100600, 0, true).is_some());
    }

    /// On the filesystem: the reader's own key file is read when only its owner reads it, and
    /// refused when its group may read it or when the path is a link to it.
    #[cfg(unix)]
    #[test]
    fn the_reader_reads_its_own_key_file_named_and_private_only() {
        use std::os::unix::fs::PermissionsExt as _;

        let folder = std::env::temp_dir().join(format!(
            "permguard-secret-file-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |elapsed| elapsed.as_nanos())
        ));
        std::fs::create_dir_all(&folder).expect("the folder");
        let file = folder.join("secret.key");
        std::fs::write(&file, "secret_key: pgsk_test\n").expect("written");
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).expect("0600");
        assert!(read_secret_file(&file).is_ok());

        let link = folder.join("linked.key");
        std::os::unix::fs::symlink(&file, &link).expect("the link");
        let refused = read_secret_file(&link).expect_err("a link to the reader's own file");
        assert!(refused.message.contains("is a link"), "{}", refused.message);

        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o640)).expect("0640");
        let refused = read_secret_file(&file).expect_err("readable by its group");
        assert!(refused.message.contains("chmod 600"), "{}", refused.message);
        let _ = std::fs::remove_dir_all(&folder);
    }

    /// A token is kept apart for every access key, secret key, Authority Plane and scope: one
    /// client's token is never another's, and the name keeps nothing of the secret.
    #[test]
    fn every_client_keeps_its_token_apart() {
        let name = |key, secret, endpoint, scope| cache_name(key, secret, endpoint, scope);
        let one = name("pgak_A", "pgsk_a", "https://authority:8443", None);
        assert_eq!(
            one,
            name("pgak_A", "pgsk_a", "https://authority:8443", None)
        );
        assert_eq!(one.len(), 32);
        for other in [
            name("pgak_B", "pgsk_a", "https://authority:8443", None),
            name("pgak_A", "pgsk_b", "https://authority:8443", None),
            name("pgak_A", "pgsk_a", "https://other:8443", None),
            name(
                "pgak_A",
                "pgsk_a",
                "https://authority:8443",
                Some("catalog.read@plane/control"),
            ),
        ] {
            assert_ne!(one, other);
        }
        assert!(!one.contains("pgsk"));
    }
}
