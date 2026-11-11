// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The administrator (`2-security/8` The administrator): `admin`, made at the Authority Plane's
//! first start with every scope and a first access key, whose secret is written once to
//! `planes/authority/admin.key`, owner-only, and never to the log. When every key is lost,
//! [`offline_key`], the server stopped, makes a new one and writes it there; the next start
//! records it in the audit trail.

use std::io::Write as _;
use std::path::{Path, PathBuf};

use zeroize::Zeroizing;

use crate::access_keys;
use crate::accounts::{self, AccessKey, Account, Accounts};

/// The file the administrator's key is written to, below `planes/authority/`.
pub const KEY_FILE: &str = "admin.key";
/// The mark an offline key leaves for the next start to record.
pub const OFFLINE_MARK: &str = "admin-key.offline";

/// What a key file holds: the access key and its secret key, one per line.
pub fn key_file_text(access_key: &str, secret_key: &str) -> Zeroizing<String> {
    Zeroizing::new(format!(
        "access_key: {access_key}\nsecret_key: {secret_key}\n"
    ))
}

/// A new file at `path`, readable and writable by its owner alone; refused when the file exists,
/// so no key is ever overwritten.
fn create_owner_only(path: &Path) -> std::io::Result<std::fs::File> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    options.open(path)
}

/// Writes `text` into `file` and makes it durable.
fn fill(mut file: std::fs::File, text: &str) -> std::io::Result<()> {
    file.write_all(text.as_bytes())?;
    file.sync_all()
}

/// Writes `text` to a new file at `path`, readable and writable by its owner alone; refused when
/// the file exists, so no key is ever overwritten.
pub fn write_owner_only(path: &Path, text: &str) -> std::io::Result<()> {
    fill(create_owner_only(path)?, text)
}

/// Makes a key for `account` and writes it to `path`. The file is claimed first, so a path that
/// is taken changes nothing; then the account is written, so a crash leaves a key nobody holds
/// rather than a file naming a key that does not exist.
fn new_key(
    accounts: &Accounts,
    account: Account,
    path: &Path,
    by: &str,
    now: u64,
) -> Result<String, String> {
    let file = create_owner_only(path).map_err(|error| format!("{}: {error}", path.display()))?;
    let made = (|| {
        let access_key = access_keys::draw_access_key()?;
        let secret = access_keys::draw_secret_key()?;
        let secret_hash = access_keys::hash(&secret)?;
        let mut keys: Vec<AccessKey> = account.keys.clone();
        // Room for the new key: the oldest live keys of a full account go, as the operator asked.
        while keys.iter().filter(|key| key.is_live(now)).count() >= accounts::MAX_LIVE_KEYS {
            keys.remove(0);
        }
        keys.push(AccessKey {
            access_key: access_key.clone(),
            secret_hash,
            created_at: now,
            expires_at: None,
        });
        accounts
            .put(None, Account { keys, ..account }, by, now)
            .map_err(|error| error.to_string())?;
        Ok::<_, String>((access_key, secret))
    })();
    let (access_key, secret) = match made {
        Ok(made) => made,
        Err(error) => {
            // Nothing was written to it: the claimed file goes, so the path is free again.
            let _ = std::fs::remove_file(path);
            return Err(error);
        }
    };
    fill(file, &key_file_text(&access_key, &secret))
        .map_err(|error| format!("writing {}: {error}", path.display()))?;
    Ok(access_key)
}

/// Makes `admin` when the plane holds none: its scopes, a first key written to the key file.
/// Answers the key made, `None` when `admin` existed.
pub fn ensure(accounts: &Accounts, plane_dir: &Path, now: u64) -> Result<Option<String>, String> {
    if accounts.get(accounts::ADMIN).is_some() {
        return Ok(None);
    }
    let path = plane_dir.join(KEY_FILE);
    // A file a crash left before the account was written names no key: it goes.
    if std::fs::read_to_string(&path).is_ok_and(|text| access_key_of(&text).is_none()) {
        std::fs::remove_file(&path).map_err(|error| format!("{}: {error}", path.display()))?;
    }
    if path.exists() {
        return Err(format!(
            "{} exists and no `admin` is held: remove the file, which names no live key, and start \
             again",
            path.display()
        ));
    }
    let admin = Account::new(
        accounts::ADMIN,
        "The Authority Plane's administrator",
        accounts::admin_scopes(),
        now,
    );
    new_key(accounts, admin, &path, "authority", now).map(Some)
}

/// A new key for `admin`, made offline with the server stopped: the way in when every key is lost.
/// Written to `secret_out`, a new owner-only file; the next start records it.
pub fn offline_key(
    accounts: &Accounts,
    plane_dir: &Path,
    secret_out: &Path,
    now: u64,
) -> Result<String, String> {
    let admin = accounts.get(accounts::ADMIN).unwrap_or_else(|| {
        Account::new(
            accounts::ADMIN,
            "The Authority Plane's administrator",
            accounts::admin_scopes(),
            now,
        )
    });
    let access_key = new_key(accounts, admin, secret_out, "offline", now)?;
    let mark = plane_dir.join(OFFLINE_MARK);
    std::fs::write(&mark, format!("{access_key}\n"))
        .map_err(|error| format!("writing {}: {error}", mark.display()))?;
    Ok(access_key)
}

/// The access key an offline command made since the last start, the mark removed: what the start
/// records in the audit trail.
pub fn take_offline_mark(plane_dir: &Path) -> Option<String> {
    let mark: PathBuf = plane_dir.join(OFFLINE_MARK);
    let text = std::fs::read_to_string(&mark).ok()?;
    let _ = std::fs::remove_file(&mark);
    Some(text.trim().to_owned()).filter(|key| access_keys::is_access_key(key))
}

/// The secret key a file holds: the `secret_key:` line of a key file, or the whole file trimmed.
pub fn secret_of(text: &str) -> Option<String> {
    text.lines()
        .find_map(|line| line.trim().strip_prefix("secret_key:"))
        .map(|secret| secret.trim().to_owned())
        .or_else(|| Some(text.trim().to_owned()))
        .filter(|secret| access_keys::is_secret_key(secret))
}

/// The access key a key file names.
pub fn access_key_of(text: &str) -> Option<String> {
    text.lines()
        .find_map(|line| line.trim().strip_prefix("access_key:"))
        .map(|key| key.trim().to_owned())
        .filter(|key| access_keys::is_access_key(key))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;
    use permguard_host::storage::dir::Dir;
    use permguard_host::storage::journal::Options;

    fn scratch(tag: &str) -> PathBuf {
        let root =
            std::env::temp_dir().join(format!("pg-authority-admin-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("scratch");
        root
    }

    #[test]
    fn the_first_start_makes_admin_once_and_writes_its_key_owner_only() {
        let root = scratch("first");
        let (accounts, _) =
            Accounts::open(&Dir::open(&root).expect("a dir"), Options::default()).expect("opens");
        let key = ensure(&accounts, &root, 10).expect("made").expect("a key");
        let text = std::fs::read_to_string(root.join(KEY_FILE)).expect("written");
        assert_eq!(access_key_of(&text).as_deref(), Some(key.as_str()));
        let secret = secret_of(&text).expect("a secret");
        let admin = accounts.get(accounts::ADMIN).expect("admin");
        assert!(access_keys::verify(
            &secret,
            &admin.key(&key).expect("held").secret_hash
        ));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = std::fs::metadata(root.join(KEY_FILE))
                .expect("metadata")
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        assert_eq!(ensure(&accounts, &root, 11).expect("held"), None, "once");
        // Offline, a new key beside the first; a third replaces the oldest.
        let out = root.join("lost.key");
        let second = offline_key(&accounts, &root, &out, 20).expect("made");
        assert_eq!(take_offline_mark(&root).as_deref(), Some(second.as_str()));
        assert_eq!(take_offline_mark(&root), None);
        assert!(
            offline_key(&accounts, &root, &out, 30).is_err(),
            "never overwrites"
        );
        let third = offline_key(&accounts, &root, &root.join("third.key"), 30).expect("made");
        let admin = accounts.get(accounts::ADMIN).expect("admin");
        assert_eq!(admin.keys.len(), 2);
        assert!(admin.key(&key).is_none(), "the oldest went");
        assert!(admin.key(&third).is_some());
        assert_eq!(secret_of("  pgsk_x  "), None);
    }
}
