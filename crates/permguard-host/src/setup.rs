// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The first administrator and recovery (WP-8.2, `2-security/4` First administrator and
//! recovery).
//!
//! A Host with no administrator waits for one setup code, and only for as long as nobody
//! administers it:
//!
//! | File                  | Holds                                                                       |
//! | --------------------- | --------------------------------------------------------------------------- |
//! | `host/setup/state.json` | the waiting code's SHA-256, where it came from, when it expires           |
//! | `host/setup/code`     | the code itself, when the Host made it: private to the volume's owner       |
//! | `host/setup/recovery.json` | a recovery started offline, until an administrator acknowledges it     |
//!
//! The code never reaches a log or an answer, and the Host keeps only its digest. Whoever can
//! write the volume of a stopped server holds the Host anyway: [`Setup::start_recovery`] adds no
//! way in, it makes the one that exists explicit and recorded.
//!
//! A library, not a command: the CLI and Permguard Admin call the same functions.

use std::path::PathBuf;
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ring::rand::{SecureRandom as _, SystemRandom};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::storage::volume::Volume;
use crate::storage::{Dir, StorageError};

/// The folder under `host/`.
pub const DIRECTORY: &str = "setup";
/// The waiting code's record.
pub const STATE: &str = "state.json";
/// The code the Host made.
pub const CODE: &str = "code";
/// A recovery waiting to be acknowledged.
pub const RECOVERY: &str = "recovery.json";
/// Written once the Host is administered: from then on only a recovery makes a code.
pub const ADMINISTERED: &str = "administered";
/// What every code the Host makes begins with.
pub const CODE_PREFIX: &str = "pgsetup_";
/// The fewest characters a code supplied by a secret may have.
pub const MIN_SUPPLIED_CODE: usize = 32;
/// The capability a waiting code degrades on the Host.
pub const CAPABILITY: &str = "setup";
/// The capability a recovery not yet acknowledged degrades on the Host.
pub const RECOVERY_CAPABILITY: &str = "recovery";
/// The audit action of the first administrator made with the code.
pub const AUDIT_COMPLETED: &str = "host.setup.completed";
/// The audit action of a refused setup.
pub const AUDIT_REFUSED: &str = "host.setup.refused";
/// The audit action of a recovery started offline.
pub const AUDIT_RECOVERY_STARTED: &str = "host.recovery.started";
/// The audit action of a recovery acknowledged.
pub const AUDIT_RECOVERY_ACKNOWLEDGED: &str = "host.recovery.acknowledged";

/// Where a waiting code came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Origin {
    /// Made by the Host at a start, written to `host/setup/code`.
    Generated,
    /// The secret `host.setup.code_ref` names.
    Secret,
    /// Made offline by `host recovery start`, written to `host/setup/code`.
    Recovery,
}

impl Origin {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Generated => "generated",
            Self::Secret => "secret",
            Self::Recovery => "recovery",
        }
    }
}

/// A code waiting to be used: never the code itself.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Waiting {
    /// The hex SHA-256 of the code.
    pub digest: String,
    pub origin: Origin,
    /// Unix seconds.
    pub made_at: u64,
    /// Unix seconds.
    pub expires_at: u64,
    /// The user a setup was making when it stopped: the same name finishes it.
    #[serde(default)]
    pub pending: Option<String>,
}

/// A recovery started offline, until an administrator acknowledges it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryRecord {
    /// Unix seconds.
    pub started_at: u64,
    pub reason: String,
    /// The administrator the recovery's code made: it does not acknowledge the recovery while
    /// another administrator exists, who has to see it.
    #[serde(default)]
    pub made: Option<String>,
}

/// What a start serves.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Prepared {
    /// An administrator exists and no recovery code waits: the setup route answers `404`.
    Closed,
    /// A code waits; `code_file` is where it is when the Host made it.
    Waiting {
        waiting: Waiting,
        code_file: Option<PathBuf>,
    },
    /// The Host was administered once and nobody administers it now: no code is made again by
    /// itself, a recovery is the way back.
    Orphaned,
    /// The code the deployment supplied expired: a new secret value, or a recovery, is needed.
    Expired,
}

/// The setup folder of one volume.
#[derive(Debug)]
pub struct Setup {
    dir: Dir,
    /// Held across a setup: one code makes one administrator, however many ask at once.
    taking: std::sync::Mutex<()>,
}

fn corrupt(what: &str, error: impl std::fmt::Display) -> StorageError {
    StorageError::Corruption(format!("{what}: {error}"))
}

/// The hex SHA-256 of `code`, trimmed.
pub fn digest(code: &str) -> String {
    Sha256::digest(code.trim().as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// Whether `a` and `b` are equal, in a time that does not depend on where they differ.
fn same(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |held, (x, y)| held | (x ^ y)) == 0
}

/// A new code: 256 random bits.
fn new_code() -> Result<String, StorageError> {
    let mut bytes = [0u8; 32];
    SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| corrupt("making a setup code", "the system's randomness failed"))?;
    Ok(format!("{CODE_PREFIX}{}", URL_SAFE_NO_PAD.encode(bytes)))
}

impl Setup {
    /// The setup folder of `volume`, made when absent.
    pub fn open(volume: &Volume) -> Result<Self, StorageError> {
        Ok(Self {
            dir: volume.host().subdir(DIRECTORY, true)?,
            taking: std::sync::Mutex::new(()),
        })
    }

    /// Where the Host writes the code it makes.
    pub fn code_path(&self) -> PathBuf {
        self.dir.child_path(CODE)
    }

    /// The code waiting, when one does.
    pub fn waiting(&self) -> Result<Option<Waiting>, StorageError> {
        self.dir
            .read(STATE)?
            .map(|bytes| serde_json::from_slice(&bytes).map_err(|error| corrupt(STATE, error)))
            .transpose()
    }

    /// The recovery waiting to be acknowledged, when one does.
    pub fn recovery(&self) -> Result<Option<RecoveryRecord>, StorageError> {
        self.dir
            .read(RECOVERY)?
            .map(|bytes| serde_json::from_slice(&bytes).map_err(|error| corrupt(RECOVERY, error)))
            .transpose()
    }

    fn write_state(&self, waiting: &Waiting) -> Result<(), StorageError> {
        let bytes = serde_json::to_vec_pretty(waiting).map_err(|error| corrupt(STATE, error))?;
        crate::storage::write::replace_bytes(&self.dir, STATE, &bytes)
    }

    fn make(&self, origin: Origin, expires: Duration, now: u64) -> Result<Waiting, StorageError> {
        let code = zeroize::Zeroizing::new(new_code()?);
        crate::storage::write::replace_bytes(&self.dir, CODE, format!("{}\n", *code).as_bytes())?;
        let waiting = Waiting {
            digest: digest(&code),
            origin,
            made_at: now,
            expires_at: now.saturating_add(expires.as_secs()),
            pending: None,
        };
        self.write_state(&waiting)?;
        Ok(waiting)
    }

    /// Removes the code and its record: nothing waits any more.
    pub fn close(&self) -> Result<(), StorageError> {
        let removed = self.dir.unlink(CODE)? | self.dir.unlink(STATE)?;
        if removed {
            self.dir.sync()?;
        }
        Ok(())
    }

    /// Whether the Host was ever administered.
    pub fn was_administered(&self) -> Result<bool, StorageError> {
        self.dir.exists(ADMINISTERED)
    }

    fn mark_administered(&self) -> Result<(), StorageError> {
        if !self.dir.exists(ADMINISTERED)? {
            crate::storage::write::replace_bytes(&self.dir, ADMINISTERED, b"")?;
        }
        Ok(())
    }

    /// What a start serves. A code only the first time the Host has no administrator, or after a
    /// recovery started offline; nothing once an administrator exists; and, when the Host was
    /// administered before and nobody administers it now, nothing either: a recovery is the way
    /// back, never a code that reappears by itself. `supplied` is the secret
    /// `host.setup.code_ref` names; its expiry runs from the first start that armed it.
    pub fn prepare(
        &self,
        administered: bool,
        supplied: Option<&str>,
        expires: Duration,
        now: u64,
    ) -> Result<Prepared, StorageError> {
        let held = self.waiting()?;
        let live = held.as_ref().filter(|waiting| waiting.expires_at > now);
        let recovering = live.filter(|waiting| waiting.origin == Origin::Recovery);
        if let Some(waiting) = recovering {
            return Ok(Prepared::Waiting {
                waiting: waiting.clone(),
                code_file: Some(self.code_path()),
            });
        }
        if administered {
            self.mark_administered()?;
            self.close()?;
            return Ok(Prepared::Closed);
        }
        if self.was_administered()? {
            self.close()?;
            return Ok(Prepared::Orphaned);
        }
        if let Some(code) = supplied {
            let code = code.trim();
            if code.len() < MIN_SUPPLIED_CODE {
                return Err(corrupt(
                    "host.setup.code_ref",
                    format!("a setup code is at least {MIN_SUPPLIED_CODE} characters"),
                ));
            }
            let wanted = digest(code);
            // The same secret keeps the expiry of the start that first armed it.
            if let Some(armed) = held
                .as_ref()
                .filter(|waiting| waiting.origin == Origin::Secret && waiting.digest == wanted)
            {
                if armed.expires_at <= now {
                    return Ok(Prepared::Expired);
                }
                return Ok(Prepared::Waiting {
                    waiting: armed.clone(),
                    code_file: None,
                });
            }
            let _ = self.dir.unlink(CODE)?;
            let waiting = Waiting {
                digest: wanted,
                origin: Origin::Secret,
                made_at: now,
                expires_at: now.saturating_add(expires.as_secs()),
                pending: None,
            };
            self.write_state(&waiting)?;
            return Ok(Prepared::Waiting {
                waiting,
                code_file: None,
            });
        }
        if let Some(waiting) = live.filter(|waiting| waiting.origin == Origin::Generated)
            && self.dir.exists(CODE)?
        {
            return Ok(Prepared::Waiting {
                waiting: waiting.clone(),
                code_file: Some(self.code_path()),
            });
        }
        let waiting = self.make(Origin::Generated, expires, now)?;
        Ok(Prepared::Waiting {
            waiting,
            code_file: Some(self.code_path()),
        })
    }

    /// Whether `code` is the one waiting, and has not expired.
    pub fn accepts(&self, code: &str, now: u64) -> Result<Option<Waiting>, StorageError> {
        let Some(waiting) = self.waiting()? else {
            return Ok(None);
        };
        if waiting.expires_at <= now {
            return Ok(None);
        }
        let offered = digest(code);
        Ok(same(offered.as_bytes(), waiting.digest.as_bytes()).then_some(waiting))
    }

    /// Records that a setup is making `name`: a setup that stops half-way finishes with the same
    /// name and the same code, and no other.
    pub fn mark_pending(&self, waiting: &Waiting, name: &str) -> Result<(), StorageError> {
        let mut marked = waiting.clone();
        marked.pending = Some(name.to_owned());
        self.write_state(&marked)
    }

    /// Starts a recovery, offline: a new code although administrators exist, and the record that
    /// keeps the Host `degraded: recovery` until an administrator acknowledges it.
    pub fn start_recovery(
        &self,
        reason: &str,
        expires: Duration,
        now: u64,
    ) -> Result<Waiting, StorageError> {
        let reason = reason.trim();
        if reason.is_empty() {
            return Err(corrupt("a recovery", "it states why"));
        }
        let record = RecoveryRecord {
            started_at: now,
            reason: reason.to_owned(),
            made: None,
        };
        let bytes = serde_json::to_vec_pretty(&record).map_err(|error| corrupt(RECOVERY, error))?;
        crate::storage::write::replace_bytes(&self.dir, RECOVERY, &bytes)?;
        self.make(Origin::Recovery, expires, now)
    }

    /// Acknowledges the recovery: whether one was waiting.
    pub fn acknowledge(&self) -> Result<Option<RecoveryRecord>, StorageError> {
        let held = self.recovery()?;
        if held.is_some() {
            self.dir.unlink(RECOVERY)?;
            self.dir.sync()?;
        }
        Ok(held)
    }
}

/// Why a setup was refused: what the route answers, and the audit names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refused {
    /// No code waits, or this one is not it, or it expired: one answer for all three.
    Code,
    /// The request is not one the Host can make a user of.
    Invalid(String),
    /// The Host could not record it.
    Unavailable(String),
}

/// The first administrator a setup made.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Completed {
    pub user: String,
    pub principal: String,
    /// The grant of `authz.admin` on `host`; absent when the user already held one.
    pub grant: Option<String>,
    pub origin: Origin,
}

/// What a setup asks for: the code, and the user it makes.
pub struct Request<'a> {
    pub code: &'a str,
    pub name: &'a str,
    pub email: Option<String>,
    /// Already hashed by the caller, off any runtime thread.
    pub password: Option<String>,
}

/// Makes the first administrator with the code waiting: the user, then `authz.admin` on `host`,
/// then the code is gone. A setup that stops between two steps finishes with the same code and
/// the same name; a name that is already a user is refused, so no account is promoted.
pub fn complete(
    setup: &Setup,
    mutations: &crate::operations::mutation::Mutations,
    directory: &crate::authz::directory::Directory,
    store: &crate::authz::GrantStore,
    request: Request<'_>,
    now: u64,
) -> Result<Completed, Refused> {
    use crate::authz::directory::{Change, is_user_name, user_principal};
    use crate::operations::journal::Initiator;
    use permguard_core::authz::{Principal, Resource, Selector, operations, resource_types};

    let unavailable = |error: &dyn std::fmt::Display| Refused::Unavailable(error.to_string());
    // One setup at a time, the code read again under the lock: two requests with one code make
    // one administrator, and the second finds the code gone.
    let _taking = setup
        .taking
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let waiting = setup
        .accepts(request.code, now)
        .map_err(|error| unavailable(&error))?
        .ok_or(Refused::Code)?;
    // Only a recovery's code makes an administrator beside others.
    if waiting.origin != Origin::Recovery && administered(store, now) {
        setup.close().map_err(|error| unavailable(&error))?;
        return Err(Refused::Code);
    }
    let name = request.name.trim().to_ascii_lowercase();
    if !is_user_name(&name) {
        return Err(Refused::Invalid(format!(
            "`{name}` is not a user name: 1 to 128 lowercase letters, digits, `.`, `_`, `-`, `+` or `@`"
        )));
    }
    if request.email.is_none() && request.password.is_none() {
        return Err(Refused::Invalid(
            "the first administrator signs in somehow: a password, an email its provider links, or both"
                .to_owned(),
        ));
    }
    let finishing = waiting.pending.as_deref() == Some(name.as_str());
    if let Some(other) = waiting
        .pending
        .as_deref()
        .filter(|pending| *pending != name)
    {
        return Err(Refused::Invalid(format!(
            "a setup is finishing the user `{other}`: finish it with that name"
        )));
    }
    if directory.user(&name).is_some() && !finishing {
        return Err(Refused::Invalid(format!(
            "`{name}` is already a user: the first administrator is a new one"
        )));
    }
    setup
        .mark_pending(&waiting, &name)
        .map_err(|error| unavailable(&error))?;
    if directory.user(&name).is_none() {
        crate::operations::directory::change(
            mutations,
            directory,
            Initiator::System("setup".to_owned()),
            Change::CreateUser {
                name: name.clone(),
                email: request.email.clone(),
                display: None,
                password: request.password,
            },
            "setup",
            now,
            None,
        )
        .map_err(|error| Refused::Invalid(error.to_string()))?;
    }
    let principal = user_principal(&name);
    let admin = Principal::new(principal.as_str()).map_err(|error| unavailable(&error))?;
    let holds = store
        .allows_at(now)
        .permits(&admin, operations::AUTHZ_ADMIN, &Resource::host());
    let grant = if holds {
        None
    } else {
        Some(
            crate::operations::grants::issue(
                mutations,
                store,
                Initiator::System("setup".to_owned()),
                crate::authz::Issue {
                    principal: admin,
                    operations: vec![operations::AUTHZ_ADMIN.to_owned()],
                    selector: Selector::exactly(Resource::host()),
                    resource_types: vec![resource_types::HOST.to_owned()],
                    constraints: [("bootstrap".to_owned(), "setup code".to_owned())].into(),
                    issued_by: "setup".to_owned(),
                    expires_at: None,
                },
                now,
            )
            .map_err(|error| unavailable(&error))?
            .grant_id
            .to_string(),
        )
    };
    // A recovery's administrator is named on the recovery, which it does not acknowledge alone.
    if waiting.origin == Origin::Recovery
        && let Some(mut record) = setup.recovery().map_err(|error| unavailable(&error))?
    {
        record.made = Some(principal.clone());
        let bytes = serde_json::to_vec_pretty(&record).map_err(|error| unavailable(&error))?;
        crate::storage::write::replace_bytes(&setup.dir, RECOVERY, &bytes)
            .map_err(|error| unavailable(&error))?;
    }
    setup
        .mark_administered()
        .map_err(|error| unavailable(&error))?;
    setup.close().map_err(|error| unavailable(&error))?;
    Ok(Completed {
        user: name,
        principal,
        grant,
        origin: waiting.origin,
    })
}

/// Whether anybody administers the Host: an active grant of `authz.admin` on `host`, held by any
/// principal but `anonymous`.
pub fn administered(store: &crate::authz::GrantStore, now: u64) -> bool {
    use permguard_core::authz::{ANONYMOUS, Resource, operations, resource_types};
    let host = Resource::host();
    store
        .records()
        .iter()
        .filter(|record| record.is_active_at(now))
        .flat_map(crate::authz::record::GrantRecord::allows)
        .any(|allow| {
            allow.principal.as_str() != ANONYMOUS
                && allow.operation == operations::AUTHZ_ADMIN
                && allow.selector.contains(&host)
                && (allow.resource_type == resource_types::ANY
                    || allow.resource_type == host.resource_type())
        })
}

/// Whether anybody but `principal` administers the Host: what an offline bootstrap of
/// `principal` is refused for.
pub fn administered_by_another(
    store: &crate::authz::GrantStore,
    principal: &str,
    now: u64,
) -> bool {
    use permguard_core::authz::{ANONYMOUS, Resource, operations, resource_types};
    let host = Resource::host();
    store
        .records()
        .iter()
        .filter(|record| record.is_active_at(now))
        .flat_map(crate::authz::record::GrantRecord::allows)
        .any(|allow| {
            allow.principal.as_str() != ANONYMOUS
                && allow.principal.as_str() != principal
                && allow.operation == operations::AUTHZ_ADMIN
                && allow.selector.contains(&host)
                && (allow.resource_type == resource_types::ANY
                    || allow.resource_type == host.resource_type())
        })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;
    use permguard_core::assurance::AssuranceProfile;

    const DAY: Duration = Duration::from_secs(86_400);

    fn setup(tag: &str) -> (Setup, Volume) {
        let root = std::env::temp_dir().join(format!("pg-setup-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("scratch");
        let volume = Volume::claim(&root, AssuranceProfile::Development).expect("claimed");
        (Setup::open(&volume).expect("opened"), volume)
    }

    fn setup_named(tag: &str) -> (Setup, Volume) {
        setup(tag)
    }

    fn code_of(setup: &Setup) -> String {
        std::fs::read_to_string(setup.code_path())
            .expect("the code file")
            .trim()
            .to_owned()
    }

    #[test]
    fn a_host_without_an_administrator_waits_for_one_code_kept_only_as_its_digest() {
        let (setup, _volume) = setup("first");
        let Prepared::Waiting { waiting, code_file } =
            setup.prepare(false, None, DAY, 1_000).expect("prepared")
        else {
            panic!("a code waits");
        };
        assert_eq!(waiting.origin, Origin::Generated);
        assert_eq!(code_file, Some(setup.code_path()));
        let code = code_of(&setup);
        assert!(code.starts_with(CODE_PREFIX) && code.len() > 40, "{code}");
        let state = std::fs::read_to_string(setup.dir.child_path(STATE)).expect("the state");
        assert!(
            !state.contains(&code),
            "the record holds the digest, never the code"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = std::fs::metadata(setup.code_path())
                .expect("metadata")
                .permissions()
                .mode();
            assert_eq!(mode & 0o077, 0, "private to the volume's owner");
        }

        // The same code across a restart, until it expires.
        setup.prepare(false, None, DAY, 2_000).expect("again");
        assert_eq!(code_of(&setup), code);
        assert!(setup.accepts(&code, 2_000).expect("read").is_some());
        assert!(
            setup
                .accepts("pgsetup_wrong", 2_000)
                .expect("read")
                .is_none()
        );
        assert!(
            setup
                .accepts(&code, 1_000 + DAY.as_secs())
                .expect("read")
                .is_none(),
            "expired"
        );
        setup
            .prepare(false, None, DAY, 1_000 + DAY.as_secs())
            .expect("a new one");
        assert_ne!(
            code_of(&setup),
            code,
            "a start after expiry makes a new code"
        );

        // An administrator closes it, file and record.
        assert_eq!(
            setup.prepare(true, None, DAY, 5_000).expect("closed"),
            Prepared::Closed
        );
        assert!(!setup.code_path().exists());
        assert!(setup.waiting().expect("read").is_none());
    }

    /// The code makes one new user the administrator, once; a wrong code, a known name or a
    /// second use is refused, and nothing administers the Host before.
    #[test]
    fn the_code_makes_one_new_administrator_once() {
        let (setup, volume) = setup("complete");
        let (store, _) = crate::authz::GrantStore::open(&volume).expect("the grants");
        let (directory, _) =
            crate::authz::directory::Directory::open(&volume).expect("the directory");
        let mutations =
            crate::operations::mutation::Mutations::open_offline(&volume, "test").expect("engine");
        let now = crate::authz::store::now();
        assert!(!administered(&store, now));
        setup.prepare(false, None, DAY, now).expect("prepared");
        let code = code_of(&setup);
        fn ask<'a>(code: &'a str, name: &'a str) -> Request<'a> {
            Request {
                code,
                name,
                email: Some(format!("{name}@acme.example")),
                password: None,
            }
        }

        assert_eq!(
            complete(
                &setup,
                &mutations,
                &directory,
                &store,
                ask("pgsetup_wrong", "alice"),
                now
            ),
            Err(Refused::Code)
        );
        assert!(matches!(
            complete(
                &setup,
                &mutations,
                &directory,
                &store,
                Request {
                    code: &code,
                    name: "alice",
                    email: None,
                    password: None
                },
                now
            ),
            Err(Refused::Invalid(_))
        ));
        let made = complete(
            &setup,
            &mutations,
            &directory,
            &store,
            ask(&code, "Alice"),
            now,
        )
        .expect("the first administrator");
        assert_eq!(made.user, "alice");
        assert!(made.grant.is_some());
        assert!(administered(&store, now));
        assert!(!administered_by_another(&store, "user:alice", now));
        assert!(administered_by_another(&store, "user:bob", now));
        assert!(!setup.code_path().exists(), "the code is gone");
        assert_eq!(
            complete(
                &setup,
                &mutations,
                &directory,
                &store,
                ask(&code, "bob"),
                now
            ),
            Err(Refused::Code),
            "once"
        );

        // A recovery code never promotes a user that exists.
        setup.start_recovery("lost", DAY, now).expect("started");
        let recovery = code_of(&setup);
        assert!(matches!(
            complete(
                &setup,
                &mutations,
                &directory,
                &store,
                ask(&recovery, "alice"),
                now
            ),
            Err(Refused::Invalid(_))
        ));
        let rescued = complete(
            &setup,
            &mutations,
            &directory,
            &store,
            ask(&recovery, "carol"),
            now,
        )
        .expect("a new administrator");
        assert_eq!(rescued.origin, Origin::Recovery);
        assert!(
            setup.recovery().expect("read").is_some(),
            "acknowledged separately"
        );
    }

    /// Once administered, a Host never makes a code by itself again, even with nobody
    /// administering it: a recovery is the way back. A supplied code keeps its first expiry.
    #[test]
    fn a_code_appears_only_the_first_time_and_a_supplied_one_expires_for_good() {
        let (setup, _volume) = setup("once");
        setup.prepare(false, None, DAY, 10).expect("first");
        assert_eq!(
            setup.prepare(true, None, DAY, 20).expect("closed"),
            Prepared::Closed
        );
        assert_eq!(
            setup.prepare(false, None, DAY, 30).expect("orphaned"),
            Prepared::Orphaned
        );
        assert!(!setup.code_path().exists(), "no code reappears");
        setup
            .start_recovery("the grants expired", DAY, 40)
            .expect("recovery");
        assert!(matches!(
            setup.prepare(false, None, DAY, 50).expect("recovering"),
            Prepared::Waiting { .. }
        ));

        let (secret, _volume) = setup_named("secret-expiry");
        let supplied = "a-code-the-deployment-keeps-in-a-secret-0123";
        secret
            .prepare(false, Some(supplied), DAY, 10)
            .expect("armed");
        assert!(matches!(
            secret
                .prepare(false, Some(supplied), DAY, 10 + DAY.as_secs() / 2)
                .expect("again"),
            Prepared::Waiting { .. }
        ));
        assert_eq!(
            secret
                .prepare(false, Some(supplied), DAY, 11 + DAY.as_secs())
                .expect("expired"),
            Prepared::Expired,
            "a restart does not re-arm the same secret"
        );
    }

    /// Two setups at once with one code: one administrator.
    #[test]
    fn two_setups_with_one_code_make_one_administrator() {
        let (setup, volume) = setup("race");
        let (store, _) = crate::authz::GrantStore::open(&volume).expect("the grants");
        let (directory, _) =
            crate::authz::directory::Directory::open(&volume).expect("the directory");
        let mutations =
            crate::operations::mutation::Mutations::open_offline(&volume, "test").expect("engine");
        let now = crate::authz::store::now();
        setup.prepare(false, None, DAY, now).expect("prepared");
        let code = code_of(&setup);
        let made: Vec<bool> = std::thread::scope(|scope| {
            let handles: Vec<_> = ["alice", "mallory"]
                .into_iter()
                .map(|name| {
                    let (setup, mutations, directory, store, code) =
                        (&setup, &mutations, &directory, &store, &code);
                    scope.spawn(move || {
                        complete(
                            setup,
                            mutations,
                            directory,
                            store,
                            Request {
                                code,
                                name,
                                email: Some(format!("{name}@acme.example")),
                                password: None,
                            },
                            now,
                        )
                        .is_ok()
                    })
                })
                .collect();
            handles
                .into_iter()
                .map(|handle| handle.join().expect("joined"))
                .collect()
        });
        assert_eq!(made.iter().filter(|made| **made).count(), 1, "{made:?}");
    }

    #[test]
    fn a_supplied_code_writes_no_file_and_is_long_enough() {
        let (setup, _volume) = setup("secret");
        assert!(setup.prepare(false, Some("short"), DAY, 10).is_err());
        let supplied = "a-code-the-deployment-keeps-in-a-secret-0123";
        let Prepared::Waiting { waiting, code_file } = setup
            .prepare(false, Some(supplied), DAY, 10)
            .expect("prepared")
        else {
            panic!("a code waits");
        };
        assert_eq!((waiting.origin, code_file), (Origin::Secret, None));
        assert!(!setup.code_path().exists());
        assert!(setup.accepts(supplied, 20).expect("read").is_some());
    }

    #[test]
    fn a_recovery_waits_although_administered_and_until_acknowledged() {
        let (setup, _volume) = setup("recovery");
        assert!(setup.start_recovery("  ", DAY, 10).is_err(), "a reason");
        setup
            .start_recovery("every administrator left", DAY, 10)
            .expect("started");
        let Prepared::Waiting { waiting, .. } =
            setup.prepare(true, None, DAY, 20).expect("prepared")
        else {
            panic!("the recovery code waits although administrators exist");
        };
        assert_eq!(waiting.origin, Origin::Recovery);
        setup.close().expect("used");
        assert_eq!(
            setup.prepare(true, None, DAY, 30).expect("closed"),
            Prepared::Closed
        );
        assert_eq!(
            setup.acknowledge().expect("acknowledged").map(|r| r.reason),
            Some("every administrator left".to_owned())
        );
        assert!(setup.recovery().expect("read").is_none());
    }
}
