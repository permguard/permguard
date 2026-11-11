// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The command line as a service account (`2-security/7` The client): its access key and secret
//! key, from the flags or the configuration, obtain a token at the Authority Plane's token
//! endpoint; every command that reaches a Plane or a Host API sends it when no `--token-file` is
//! given. The token is kept under `~/.permguard/tokens/`, in a file only its owner reads, keyed by
//! the access key, the Authority Plane and what it asked for, and reused until a minute before it
//! expires. Nothing here traces a secret or a token: the trace names the access key and the expiry.

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

/// The client the flags or the configuration name, when there is one: its token source. A key
/// file names its access key itself, so `--secret-key-file` alone is enough.
pub fn source(
    globals: &Globals,
    store: &Store,
    trace: &Trace,
) -> Result<Option<TokenSource>, Failure> {
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
    let held = private_file(&secret_file, "the secret key file")?;
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
    TokenSource::new(&endpoint, &access_key, secret, scope(store), tls)
        .map(Some)
        .map_err(|failure| Failure::from_client(&failure))
}

/// The configured client's token, from the cache while it serves, else obtained now: `None`
/// without a client.
pub fn token(
    globals: &Globals,
    store: &Store,
    trace: &Trace,
) -> Result<Option<Credential>, Failure> {
    let Some(source) = source(globals, store, trace)? else {
        return Ok(None);
    };
    let cache = cache_path(globals, store);
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
    Ok(Some(issued.token))
}

/// Drops the token kept for the configured client: a surface refused it, revoked or suspended,
/// and the next command obtains another rather than sending it again.
pub fn forget(globals: &Globals, store: &Store) {
    if let Some(path) = cache_path(globals, store) {
        let _ = std::fs::remove_file(path);
    }
}

/// Where the token for this client is kept: none without a home directory.
fn cache_path(globals: &Globals, store: &Store) -> Option<PathBuf> {
    let home = crate::settings::home_directory().ok()?;
    // Not a secret, a name: which key, where, for what.
    let key = format!(
        "{}\n{}\n{}",
        access_key(globals, store).unwrap_or_default(),
        authority_endpoint(globals, store).unwrap_or_default(),
        scope(store).unwrap_or_default()
    );
    let digest = ring::digest::digest(&ring::digest::SHA256, key.as_bytes());
    let name: String = digest.as_ref()[..16]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    Some(
        home.join(".permguard")
            .join("tokens")
            .join(format!("{name}.json")),
    )
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
    (expires_at > now + REFRESH_AHEAD.as_secs()).then(|| Issued {
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
