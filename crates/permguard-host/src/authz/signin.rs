// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! Password sign-in (WP-8.1, `1-architecture/1` Local users and authentication methods, and
//! `6-contracts/8` Sign-in): a name, a password and, when the user has a second factor or the
//! deployment requires one, a code, for a session.
//!
//! | Rule        | Here                                                                                   |
//! | ----------- | -------------------------------------------------------------------------------------- |
//! | one refusal | an unknown user, a wrong password, a disabled or locked user and a wrong code are one [`Refused`], after the same hashing work |
//! | lockout     | [`super::lockout::Lockout`]: a locked user's password is never checked                 |
//! | factor      | sealed under the Host-local root's `mfa.seal` key for the user; one that cannot be unsealed refuses |
//! | `required`  | a user without a factor gets a session that serves only its enrollment                 |
//! | changes     | a password or a factor is one directory operation, initiated by the user               |
//!
//! Nothing here is logged with a secret: the log names the user, the source and the reason.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use zeroize::Zeroizing;

use super::directory::{Change, Directory, UserStatus, user_principal};
use super::lockout::Lockout;
use super::sessions::{Opened, Session, Sessions};
use super::{factor, password};
use crate::operations::journal::Initiator;
use crate::operations::mutation::Mutations;

/// Whether a password sign-in asks for a second factor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mfa {
    /// Never asked, never enrolled.
    Off,
    /// Asked of the users who enrolled one.
    Optional,
    /// Asked of every user; one without a factor enrolls before anything else.
    Required,
}

impl Mfa {
    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "off" => Some(Self::Off),
            "optional" => Some(Self::Optional),
            "required" => Some(Self::Required),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::Optional => "optional",
            Self::Required => "required",
        }
    }
}

/// The password policy of `host.authentication.password`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Policy {
    pub min_length: usize,
    pub mfa: Mfa,
}

/// The key a user's factor is sealed under: the Host-local root's `mfa.seal` key for that user.
/// `None` where the Host has no local root: no factor can be enrolled or checked there.
pub type Sealer = Arc<dyn Fn(&str) -> Option<Zeroizing<[u8; 32]>> + Send + Sync>;

/// A refused sign-in. What the caller is told is the same whatever failed; [`Refused::reason`]
/// is for the log and the audit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refused {
    pub reason: &'static str,
}

/// Why a change a signed-in user asked for was refused: what the user may be told.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChangeRefused(pub String);

impl std::fmt::Display for ChangeRefused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// An enrollment waiting for its confirming code: the secret, and when it was made.
type Pending = (Zeroizing<Vec<u8>>, Duration);

/// How long an enrollment waits for its confirming code.
pub const ENROLLMENT_WINDOW: Duration = Duration::from_secs(600);

/// The password sign-in of one Host.
pub struct SignIn {
    directory: Arc<Directory>,
    sessions: Arc<Sessions>,
    mutations: Arc<Mutations>,
    lockout: Lockout,
    policy: Policy,
    sealer: Option<Sealer>,
    /// What an authenticator application names the Host by.
    label: String,
    /// The last step each user's code was accepted at: each code once.
    used: Mutex<HashMap<String, u64>>,
    /// Enrollments waiting for their confirming code: the secret and when it was made.
    pending: Mutex<HashMap<String, Pending>>,
    time: Arc<crate::time::TimeGuard>,
}

impl std::fmt::Debug for SignIn {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SignIn")
            .field("policy", &self.policy)
            .field("factors", &self.sealer.is_some())
            .finish_non_exhaustive()
    }
}

impl SignIn {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        directory: Arc<Directory>,
        sessions: Arc<Sessions>,
        mutations: Arc<Mutations>,
        lockout: Lockout,
        policy: Policy,
        sealer: Option<Sealer>,
        label: impl Into<String>,
        time: Arc<crate::time::TimeGuard>,
    ) -> Self {
        Self {
            directory,
            sessions,
            mutations,
            lockout,
            policy,
            sealer,
            label: label.into(),
            used: Mutex::new(HashMap::new()),
            pending: Mutex::new(HashMap::new()),
            time,
        }
    }

    pub fn policy(&self) -> Policy {
        self.policy
    }

    pub fn lockout(&self) -> &Lockout {
        &self.lockout
    }

    pub fn sessions(&self) -> &Arc<Sessions> {
        &self.sessions
    }

    /// Signs `name` in with `password` and, when asked, `code`, from `source`.
    pub fn sign_in(
        &self,
        name: &str,
        secret: &str,
        code: Option<&str>,
        source: Option<IpAddr>,
    ) -> Result<(String, Session), Refused> {
        let name = name.trim().to_ascii_lowercase();
        let refuse = |reason: &'static str, failed: bool| {
            if failed {
                self.lockout.failed(&name, source);
            }
            tracing::info!(
                event.name = "host.signin_refused",
                component = "host",
                user = %name,
                source = ?source,
                reason,
                "a password sign-in was refused"
            );
            Err(Refused { reason })
        };
        if self.lockout.locked(&name, source) {
            password::burn(secret);
            return refuse("locked", false);
        }
        let Some(user) = self.directory.user(&name) else {
            password::burn(secret);
            return refuse("unknown user", true);
        };
        let Some(phc) = user.password.as_deref() else {
            password::burn(secret);
            return refuse("no password", true);
        };
        if !password::verify(secret, phc) {
            return refuse("wrong password", true);
        }
        if user.status != UserStatus::Active {
            return refuse("disabled", false);
        }
        let opened = match (&user.factor, self.policy.mfa) {
            (Some(sealed), mfa) if mfa != Mfa::Off => {
                let Some(code) = code else {
                    return refuse("no code", false);
                };
                if !self.check_code(&user.name, sealed, code) {
                    return refuse("wrong code", true);
                }
                Opened::PasswordAndFactor
            }
            (_, Mfa::Required) => Opened::EnrollFactor,
            _ => Opened::Password,
        };
        self.lockout.succeeded(&name);
        let (token, session) = self
            .sessions
            .open(&user.name, opened)
            .map_err(|_| Refused {
                reason: "no session",
            })?;
        tracing::info!(
            event.name = "host.signin",
            component = "host",
            user = %user.name,
            source = ?source,
            opened = opened.as_str(),
            "a user signed in with a password"
        );
        Ok((token, session))
    }

    fn check_code(&self, name: &str, sealed: &[u8], code: &str) -> bool {
        let principal = user_principal(name);
        let Some(key) = self.sealer.as_ref().and_then(|sealer| sealer(&principal)) else {
            tracing::error!(
                event.name = "host.factor_unsealable",
                component = "host",
                user = %name,
                "a user's second factor cannot be checked: the Host has no local root"
            );
            return false;
        };
        let Some(secret) = factor::unseal(&key, &principal, sealed) else {
            tracing::error!(
                event.name = "host.factor_unsealable",
                component = "host",
                user = %name,
                "a user's second factor does not open under the Host-local root"
            );
            return false;
        };
        let mut used = self.used.lock().unwrap_or_else(PoisonError::into_inner);
        match factor::check(&secret, code, self.time.now_secs(), used.get(name).copied()) {
            Some(step) => {
                used.insert(name.to_owned(), step);
                true
            }
            None => false,
        }
    }

    /// Ends the session `token` names.
    pub fn sign_out(&self, token: &str) -> bool {
        self.sessions.end(token)
    }

    /// The live session `token` names, and its user, when the user still exists, is active and
    /// set no password since the session opened.
    pub fn session(&self, token: &str) -> Option<Session> {
        let session = self.sessions.resolve(token)?;
        let user = self.directory.user(&session.user)?;
        let current = user.status == UserStatus::Active
            && user
                .password_set_at
                .is_none_or(|set| set <= session.opened_at);
        if !current {
            self.sessions.end(token);
            return None;
        }
        Some(session)
    }

    /// Changes the password of the session's user, who proves the current one; every other
    /// session of the user ends.
    pub fn change_password(
        &self,
        token: &str,
        current: &str,
        new: &str,
    ) -> Result<(), ChangeRefused> {
        let session = self
            .session(token)
            .ok_or_else(|| ChangeRefused("the session is not valid".to_owned()))?;
        self.prove(&session.user, current)?;
        password::check_policy(&session.user, new, self.policy.min_length)
            .map_err(ChangeRefused)?;
        let phc = password::hash(new).map_err(ChangeRefused)?;
        self.write(
            &session.user,
            Change::SetPassword {
                name: session.user.clone(),
                password: phc,
            },
        )?;
        let ended = self.sessions.end_user(&session.user, Some(token));
        tracing::info!(
            event.name = "host.password_changed",
            component = "host",
            user = %session.user,
            sessions_ended = ended,
            "a user changed its password"
        );
        Ok(())
    }

    /// Starts enrolling a second factor for the session's user, who proves its password: the
    /// secret, shown once, and the URI an authenticator application scans.
    pub fn begin_factor(
        &self,
        token: &str,
        current: &str,
    ) -> Result<(String, String), ChangeRefused> {
        if self.policy.mfa == Mfa::Off {
            return Err(ChangeRefused(
                "this Host asks for no second factor".to_owned(),
            ));
        }
        if self.sealer.is_none() {
            return Err(ChangeRefused(
                "this Host has no local root to seal a second factor with".to_owned(),
            ));
        }
        let session = self
            .sessions
            .resolve(token)
            .ok_or_else(|| ChangeRefused("the session is not valid".to_owned()))?;
        self.prove(&session.user, current)?;
        let secret = factor::new_secret().map_err(ChangeRefused)?;
        let shown = (
            factor::base32(&secret),
            factor::uri(&self.label, &session.user, &secret),
        );
        self.pending
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(session.user.clone(), (secret, self.time.elapsed()));
        Ok(shown)
    }

    /// Confirms the enrollment with a code of the new factor: the factor, sealed, is in force.
    pub fn confirm_factor(&self, token: &str, code: &str) -> Result<(), ChangeRefused> {
        let session = self
            .sessions
            .resolve(token)
            .ok_or_else(|| ChangeRefused("the session is not valid".to_owned()))?;
        let now = self.time.elapsed();
        let secret = {
            let mut pending = self.pending.lock().unwrap_or_else(PoisonError::into_inner);
            pending.retain(|_, (_, at)| now.saturating_sub(*at) < ENROLLMENT_WINDOW);
            pending
                .get(&session.user)
                .map(|(secret, _)| secret.clone())
                .ok_or_else(|| ChangeRefused("no enrollment is waiting: start again".to_owned()))?
        };
        let step = factor::check(&secret, code, self.time.now_secs(), None)
            .ok_or_else(|| ChangeRefused("the code does not match".to_owned()))?;
        let principal = user_principal(&session.user);
        let key = self
            .sealer
            .as_ref()
            .and_then(|sealer| sealer(&principal))
            .ok_or_else(|| ChangeRefused("this Host has no local root".to_owned()))?;
        let sealed = factor::seal(&key, &principal, &secret).map_err(ChangeRefused)?;
        self.write(
            &session.user,
            Change::SetFactor {
                name: session.user.clone(),
                factor: Some(sealed),
            },
        )?;
        self.pending
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&session.user);
        self.used
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(session.user.clone(), step);
        // An enrollment-only session has done its work: the user signs in again with the factor.
        if session.opened == Opened::EnrollFactor {
            self.sessions.end(token);
        }
        Ok(())
    }

    fn prove(&self, name: &str, current: &str) -> Result<(), ChangeRefused> {
        let proved = self
            .directory
            .user(name)
            .and_then(|user| user.password)
            .is_some_and(|phc| password::verify(current, &phc));
        if proved {
            Ok(())
        } else {
            self.lockout.failed(name, None);
            Err(ChangeRefused(
                "the current password does not match".to_owned(),
            ))
        }
    }

    fn write(&self, name: &str, change: Change) -> Result<(), ChangeRefused> {
        let principal = user_principal(name);
        crate::operations::directory::change(
            &self.mutations,
            &self.directory,
            Initiator::Principal(principal.clone()),
            change,
            &principal,
            self.time.now_secs(),
            None,
        )
        .map(|_| ())
        .map_err(|error| ChangeRefused(error.to_string()))
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;
    use crate::operations::mutation::Applying;
    use crate::storage::volume::Volume;
    use crate::time::{ManualClock, ManualMonotonic, TimeGuard};
    use permguard_core::assurance::AssuranceProfile;

    struct World {
        signin: SignIn,
        directory: Arc<Directory>,
        mono: Arc<ManualMonotonic>,
        wall: Arc<ManualClock>,
        _root: std::path::PathBuf,
    }

    fn world(tag: &str, mfa: Mfa, sealer: bool) -> World {
        let root = std::env::temp_dir().join(format!("pg-signin-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("scratch");
        let volume = Volume::claim(&root, AssuranceProfile::Development).expect("claimed");
        let (directory, _) = Directory::open(&volume).expect("the directory");
        let mutations = Arc::new(Mutations::open_offline(&volume, "test").expect("the engine"));
        let mono = Arc::new(ManualMonotonic::default());
        let wall = Arc::new(ManualClock::at(1_800_000_000));
        let time = Arc::new(TimeGuard::new(
            wall.clone(),
            mono.clone(),
            Duration::from_secs(30),
        ));
        let phc = password::hash("a long enough secret").expect("hashed");
        for (op, name) in [(1u8, "alice"), (2, "bob")] {
            directory
                .apply(
                    &Applying::for_tests(op),
                    Change::CreateUser {
                        name: name.to_owned(),
                        email: None,
                        display: None,
                        password: Some(phc.clone()),
                    },
                    "admin",
                    1_799_999_000,
                    None,
                )
                .expect("a user");
        }
        let sealer: Option<Sealer> = sealer.then(|| {
            Arc::new(|principal: &str| {
                let mut key = Zeroizing::new([0u8; 32]);
                key[..principal.len().min(32)]
                    .copy_from_slice(&principal.as_bytes()[..principal.len().min(32)]);
                Some(key)
            }) as Sealer
        });
        let signin = SignIn::new(
            Arc::clone(&directory),
            Arc::new(Sessions::new(
                Duration::from_secs(3_600),
                Duration::from_secs(600),
                Arc::clone(&time),
            )),
            mutations,
            Lockout::new(
                3,
                Duration::from_secs(900),
                Duration::from_secs(900),
                Arc::clone(&time),
            ),
            Policy {
                min_length: 12,
                mfa,
            },
            sealer,
            "Permguard test",
            time,
        );
        World {
            signin,
            directory,
            mono,
            wall,
            _root: root,
        }
    }

    fn code(secret_b32: &str, at: u64) -> String {
        // Decodes the base32 the enrollment showed, as an authenticator application does.
        let mut bits = 0u64;
        let mut count = 0;
        let mut secret = Vec::new();
        for c in secret_b32.chars() {
            let value = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567".find(c).expect("base32") as u64;
            bits = (bits << 5) | value;
            count += 5;
            if count >= 8 {
                count -= 8;
                secret.push((bits >> count) as u8);
            }
        }
        format!("{:06}", factor::code_at(&secret, at / factor::STEP))
    }

    #[test]
    fn a_password_opens_a_session_and_every_failure_is_one_refusal() {
        let world = world("password", Mfa::Optional, true);
        let (token, session) = world
            .signin
            .sign_in("Alice", "a long enough secret", None, None)
            .expect("signed in");
        assert_eq!(session.user, "alice", "names are compared lowercased");
        assert_eq!(session.opened, Opened::Password);
        assert_eq!(world.signin.session(&token).expect("live").user, "alice");
        let wrong = world
            .signin
            .sign_in("alice", "another secret!!", None, None)
            .expect_err("refused");
        let unknown = world
            .signin
            .sign_in("nobody", "a long enough secret", None, None)
            .expect_err("refused");
        assert_eq!(
            (wrong.reason, unknown.reason),
            ("wrong password", "unknown user")
        );
        assert!(world.signin.sign_out(&token));
        assert!(world.signin.session(&token).is_none());
    }

    #[test]
    fn a_locked_user_is_refused_even_with_its_password_and_a_disabled_one_signs_in_no_more() {
        let world = world("locked", Mfa::Off, false);
        for _ in 0..3 {
            let _ = world.signin.sign_in("bob", "not the secret!!", None, None);
        }
        let locked = world
            .signin
            .sign_in("bob", "a long enough secret", None, None)
            .expect_err("locked");
        assert_eq!(locked.reason, "locked");
        world.mono.advance(Duration::from_secs(901));
        let (token, _) = world
            .signin
            .sign_in("bob", "a long enough secret", None, None)
            .expect("unlocked");
        world
            .directory
            .apply(
                &Applying::for_tests(9),
                Change::SetStatus {
                    name: "bob".to_owned(),
                    active: false,
                },
                "admin",
                1,
                None,
            )
            .expect("disabled");
        assert!(
            world.signin.session(&token).is_none(),
            "a disabled user's session ends at once"
        );
        let refused = world
            .signin
            .sign_in("bob", "a long enough secret", None, None)
            .expect_err("disabled");
        assert_eq!(refused.reason, "disabled");
    }

    #[test]
    fn a_password_change_ends_every_other_session() {
        let world = world("change", Mfa::Off, false);
        let (kept, _) = world
            .signin
            .sign_in("alice", "a long enough secret", None, None)
            .expect("signed in");
        let (other, _) = world
            .signin
            .sign_in("alice", "a long enough secret", None, None)
            .expect("signed in");
        assert!(
            world
                .signin
                .change_password(&kept, "wrong current!!", "a brand new secret")
                .is_err()
        );
        assert!(
            world
                .signin
                .change_password(&kept, "a long enough secret", "short")
                .is_err(),
            "the policy"
        );
        world.wall.jump(1);
        world
            .signin
            .change_password(&kept, "a long enough secret", "a brand new secret")
            .expect("changed");
        assert!(
            world.signin.session(&other).is_none(),
            "the other session ended"
        );
        assert!(
            world
                .signin
                .sign_in("alice", "a long enough secret", None, None)
                .is_err()
        );
        assert!(
            world
                .signin
                .sign_in("alice", "a brand new secret", None, None)
                .is_ok()
        );
    }

    #[test]
    fn an_enrolled_factor_is_asked_each_code_once_and_required_enrolls_first() {
        let world = world("factor", Mfa::Required, true);
        let (enrolling, session) = world
            .signin
            .sign_in("alice", "a long enough secret", None, None)
            .expect("signed in");
        assert_eq!(
            session.opened,
            Opened::EnrollFactor,
            "required: enroll before anything else"
        );
        let (secret, uri) = world
            .signin
            .begin_factor(&enrolling, "a long enough secret")
            .expect("begun");
        assert!(uri.contains(&secret));
        let now = 1_800_000_000;
        assert!(
            world.signin.confirm_factor(&enrolling, "000000").is_err()
                || code(&secret, now) == "000000"
        );
        world
            .signin
            .confirm_factor(&enrolling, &code(&secret, now))
            .expect("confirmed");
        assert!(
            world.signin.session(&enrolling).is_none(),
            "the enrollment session has done its work"
        );
        let held = world
            .directory
            .user("alice")
            .expect("the user")
            .factor
            .expect("sealed");
        assert!(
            !held
                .windows(secret.len())
                .any(|window| window == secret.as_bytes()),
            "never in the clear"
        );

        assert_eq!(
            world
                .signin
                .sign_in("alice", "a long enough secret", None, None)
                .expect_err("no code")
                .reason,
            "no code"
        );
        world.wall.jump(30);
        let fresh = code(&secret, now + 30);
        let (token, session) = world
            .signin
            .sign_in("alice", "a long enough secret", Some(&fresh), None)
            .expect("signed in");
        assert_eq!(session.opened, Opened::PasswordAndFactor);
        assert!(world.signin.session(&token).is_some());
        assert_eq!(
            world
                .signin
                .sign_in("alice", "a long enough secret", Some(&fresh), None)
                .expect_err("used")
                .reason,
            "wrong code",
            "each code once"
        );
    }

    #[test]
    fn without_a_local_root_no_factor_is_enrolled_and_an_enrolled_one_refuses() {
        let world = world("unsealable", Mfa::Optional, false);
        let (token, _) = world
            .signin
            .sign_in("alice", "a long enough secret", None, None)
            .expect("signed in");
        assert!(
            world
                .signin
                .begin_factor(&token, "a long enough secret")
                .unwrap_err()
                .0
                .contains("local root")
        );
        world
            .directory
            .apply(
                &Applying::for_tests(9),
                Change::SetFactor {
                    name: "bob".to_owned(),
                    factor: Some(vec![1; 48]),
                },
                "admin",
                1,
                None,
            )
            .expect("a factor");
        let refused = world
            .signin
            .sign_in("bob", "a long enough secret", Some("123456"), None)
            .expect_err("refused");
        assert_eq!(
            refused.reason, "wrong code",
            "a factor that cannot be checked never lets in"
        );
    }
}
