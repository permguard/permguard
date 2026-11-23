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
use crate::accounts::{self, AccessKey, Account, AccountStore, AccountsError};

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

/// Why [`new_key`] made no key.
enum Unmade {
    /// The first key was asked for and `admin` is held: another instance on the same store made
    /// it between this one's read and its write (iteration 03, WP-28.6).
    Held,
    /// Anything else, said.
    Failed(String),
}

/// Makes a key for `admin` and writes it to `path`. The file is claimed first, so a path that
/// is taken changes nothing; then the account is written, so a crash leaves a key nobody holds
/// rather than a file naming a key that does not exist. The key joins the keys `admin` holds
/// when it is written; an `admin` that is not held is made with it. With `first`, only an
/// `admin` that is not held is made: one held, or made meanwhile, is [`Unmade::Held`], and the
/// claimed file goes.
fn new_key(
    accounts: &dyn AccountStore,
    path: &Path,
    by: &str,
    now: u64,
    first: bool,
) -> Result<String, Unmade> {
    let file = create_owner_only(path)
        .map_err(|error| Unmade::Failed(format!("{}: {error}", path.display())))?;
    let made = (|| {
        let access_key = access_keys::draw_access_key().map_err(Unmade::Failed)?;
        let secret = access_keys::draw_secret_key().map_err(Unmade::Failed)?;
        let secret_hash = access_keys::hash(&secret).map_err(Unmade::Failed)?;
        let with_key = |account: &Account| {
            let mut keys: Vec<AccessKey> = account.keys.clone();
            // Room for the new key: the oldest live keys of a full account go, as the operator
            // asked.
            while keys.iter().filter(|key| key.is_live(now)).count() >= accounts::MAX_LIVE_KEYS {
                keys.remove(0);
            }
            keys.push(AccessKey {
                access_key: access_key.clone(),
                secret_hash: secret_hash.clone(),
                created_at: now,
                expires_at: None,
            });
            Ok(Account {
                keys,
                ..account.clone()
            })
        };
        let held = || {
            accounts
                .get(accounts::ADMIN)
                .map(|held| held.is_some())
                .map_err(|error| Unmade::Failed(error.to_string()))
        };
        let written = if held()? {
            if first {
                return Err(Unmade::Held);
            }
            accounts.update(None, accounts::ADMIN, &with_key, by, now)
        } else {
            let admin = Account::new(
                accounts::ADMIN,
                "The Authority Plane's administrator",
                accounts::admin_scopes(),
                now,
            );
            match with_key(&admin).and_then(|admin| accounts.create(None, admin, by, now)) {
                // Made meanwhile by another instance on the same store: its key is the first.
                Err(AccountsError::Conflict(_)) if first && held()? => return Err(Unmade::Held),
                written => written,
            }
        };
        written.map_err(|error| Unmade::Failed(error.to_string()))?;
        Ok((access_key, secret))
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
        .map_err(|error| Unmade::Failed(format!("writing {}: {error}", path.display())))?;
    Ok(access_key)
}

/// Makes `admin` when the plane holds none: its scopes, a first key written to the key file.
/// Answers the key made, `None` when `admin` existed. On a shared store the instances starting
/// together race for it: one makes it and writes its key, the others find it made and write none.
pub fn ensure(
    accounts: &dyn AccountStore,
    plane_dir: &Path,
    now: u64,
) -> Result<Option<String>, String> {
    if accounts
        .get(accounts::ADMIN)
        .map_err(|error| error.to_string())?
        .is_some()
    {
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
    match new_key(accounts, &path, "authority", now, true) {
        Ok(access_key) => Ok(Some(access_key)),
        Err(Unmade::Held) => Ok(None),
        Err(Unmade::Failed(error)) => Err(error),
    }
}

/// A new key for `admin`, made offline with the server stopped: the way in when every key is lost.
/// Written to `secret_out`, a new owner-only file; the next start records it.
pub fn offline_key(
    accounts: &dyn AccountStore,
    plane_dir: &Path,
    secret_out: &Path,
    now: u64,
) -> Result<String, String> {
    let access_key =
        new_key(accounts, secret_out, "offline", now, false).map_err(|unmade| match unmade {
            Unmade::Failed(error) => error,
            Unmade::Held => "`admin` is held".to_owned(),
        })?;
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
        let (accounts, _) = crate::accounts::files::FileAccounts::open(
            &Dir::open(&root).expect("a dir"),
            Options::default(),
        )
        .expect("opens");
        let key = ensure(&*accounts, &root, 10).expect("made").expect("a key");
        let text = std::fs::read_to_string(root.join(KEY_FILE)).expect("written");
        assert_eq!(access_key_of(&text).as_deref(), Some(key.as_str()));
        let secret = secret_of(&text).expect("a secret");
        let admin = accounts.get(accounts::ADMIN).expect("read").expect("admin");
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
        assert_eq!(ensure(&*accounts, &root, 11).expect("held"), None, "once");
        // Offline, a new key beside the first; a third replaces the oldest.
        let out = root.join("lost.key");
        let second = offline_key(&*accounts, &root, &out, 20).expect("made");
        assert_eq!(take_offline_mark(&root).as_deref(), Some(second.as_str()));
        assert_eq!(take_offline_mark(&root), None);
        assert!(
            offline_key(&*accounts, &root, &out, 30).is_err(),
            "never overwrites"
        );
        let third = offline_key(&*accounts, &root, &root.join("third.key"), 30).expect("made");
        let admin = accounts.get(accounts::ADMIN).expect("read").expect("admin");
        assert_eq!(admin.keys.len(), 2);
        assert!(admin.key(&key).is_none(), "the oldest went");
        assert!(admin.key(&third).is_some());
        assert_eq!(secret_of("  pgsk_x  "), None);
    }

    /// A store whose first read of `admin` is the one an instance made before another instance
    /// on the same store made it: nothing held.
    #[derive(Debug)]
    struct ReadBefore {
        store: std::sync::Arc<dyn AccountStore>,
        read: std::sync::atomic::AtomicBool,
    }

    impl AccountStore for ReadBefore {
        fn revision(&self) -> Result<u64, AccountsError> {
            self.store.revision()
        }
        fn get(&self, name: &str) -> Result<Option<Account>, AccountsError> {
            if !self.read.swap(true, std::sync::atomic::Ordering::SeqCst) {
                return Ok(None);
            }
            self.store.get(name)
        }
        fn list(&self) -> Result<Vec<Account>, AccountsError> {
            self.store.list()
        }
        fn count(&self) -> Result<usize, AccountsError> {
            self.store.count()
        }
        fn by_access_key(
            &self,
            access_key: &str,
        ) -> Result<Option<(Account, AccessKey)>, AccountsError> {
            self.store.by_access_key(access_key)
        }
        fn operation(
            &self,
            operation_id: &permguard_host::operations::journal::OperationId,
        ) -> Result<Option<(u64, String)>, AccountsError> {
            self.store.operation(operation_id)
        }
        fn create(
            &self,
            applying: Option<&permguard_host::operations::mutation::Applying<'_>>,
            account: Account,
            by: &str,
            now: u64,
        ) -> Result<Account, AccountsError> {
            self.store.create(applying, account, by, now)
        }
        fn update(
            &self,
            applying: Option<&permguard_host::operations::mutation::Applying<'_>>,
            name: &str,
            change: &dyn Fn(&Account) -> Result<Account, AccountsError>,
            by: &str,
            now: u64,
        ) -> Result<Account, AccountsError> {
            self.store.update(applying, name, change, by, now)
        }
        fn delete(
            &self,
            applying: Option<&permguard_host::operations::mutation::Applying<'_>>,
            name: &str,
            allow: &dyn Fn(&Account) -> Result<(), AccountsError>,
            by: &str,
            now: u64,
        ) -> Result<(), AccountsError> {
            self.store.delete(applying, name, allow, by, now)
        }
    }

    /// Two instances on one store start together (WP-28.6): the one that made `admin` holds its
    /// first key; the other, which read before it was made, starts as well, writes no key file
    /// and adds no key.
    #[test]
    fn an_instance_that_lost_the_race_for_admin_starts_and_writes_no_key() {
        let root = scratch("race");
        let (accounts, _) = crate::accounts::files::FileAccounts::open(
            &Dir::open(&root).expect("a dir"),
            Options::default(),
        )
        .expect("opens");
        let first = root.join("first");
        let second = root.join("second");
        std::fs::create_dir_all(&first).expect("first");
        std::fs::create_dir_all(&second).expect("second");
        let key = ensure(&*accounts, &first, 10)
            .expect("made")
            .expect("a key");
        let late = ReadBefore {
            store: accounts.clone(),
            read: std::sync::atomic::AtomicBool::new(false),
        };
        assert_eq!(ensure(&late, &second, 10).expect("starts"), None);
        assert!(
            !second.join(KEY_FILE).exists(),
            "no key file on the late instance"
        );
        let admin = accounts.get(accounts::ADMIN).expect("read").expect("admin");
        assert_eq!(admin.keys.len(), 1, "the first key alone");
        assert!(admin.key(&key).is_some());
    }
}
