// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! Password sessions (WP-8.1, `2-security/3` Local users): an
//! opaque token of 256 random bits, `pgs_` then base64url, of which the Host keeps only the
//! SHA-256. A session ends `lifetime` after it opened or `idle` after its last use, whichever
//! comes first, and at sign-out, at a password change, when its user is disabled or deleted, and
//! at a restart: sessions are held in memory only.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ring::rand::{SecureRandom as _, SystemRandom};
use sha2::Digest as _;

/// What every session token starts with: how a bearer is told from a provider's token.
pub const TOKEN_PREFIX: &str = "pgs_";
/// The default lifetime and idle time.
pub const DEFAULT_LIFETIME: Duration = Duration::from_secs(8 * 3600);
pub const DEFAULT_IDLE: Duration = Duration::from_secs(3600);
/// The most sessions a Host holds, and one user: past either the oldest goes.
pub const MAX_SESSIONS: usize = 100_000;
pub const MAX_PER_USER: usize = 32;

/// How a session was opened.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Opened {
    /// A password alone.
    Password,
    /// A password and a second factor.
    PasswordAndFactor,
    /// A password, for a user who must still enroll a second factor: the session serves only
    /// that enrollment.
    EnrollFactor,
}

impl Opened {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Password => "password",
            Self::PasswordAndFactor => "password+factor",
            Self::EnrollFactor => "enroll-factor",
        }
    }
}

/// A live session, as a lookup answers it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Session {
    pub user: String,
    pub opened: Opened,
    /// Unix seconds it opened at: a password set after it ends it.
    pub opened_at: u64,
    /// Unix seconds it ends at, whatever its use.
    pub expires_at: u64,
}

#[derive(Debug, Clone)]
struct Held {
    session: Session,
    /// Monotonic readings: when it opened and when it was last used.
    started: Duration,
    used: Duration,
    /// The order it opened in: which of a user's sessions is the oldest, whatever the clock.
    sequence: u64,
}

/// The sessions of one Host.
pub struct Sessions {
    held: Mutex<HashMap<[u8; 32], Held>>,
    opened: std::sync::atomic::AtomicU64,
    lifetime: Duration,
    idle: Duration,
    time: Arc<crate::time::TimeGuard>,
}

impl std::fmt::Debug for Sessions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Sessions")
            .field("held", &self.count())
            .field("lifetime", &self.lifetime)
            .field("idle", &self.idle)
            .finish()
    }
}

fn digest(token: &str) -> [u8; 32] {
    sha2::Sha256::digest(token.as_bytes()).into()
}

impl Sessions {
    pub fn new(lifetime: Duration, idle: Duration, time: Arc<crate::time::TimeGuard>) -> Self {
        Self {
            held: Mutex::new(HashMap::new()),
            opened: std::sync::atomic::AtomicU64::new(0),
            lifetime,
            idle: idle.min(lifetime),
            time,
        }
    }

    /// How many sessions are held.
    pub fn count(&self) -> usize {
        self.held
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .len()
    }

    /// Opens a session for `user`, answering its token, shown once and never kept.
    pub fn open(&self, user: &str, opened: Opened) -> Result<(String, Session), String> {
        let mut bytes = [0u8; 32];
        SystemRandom::new()
            .fill(&mut bytes)
            .map_err(|_| "the system's random generator failed".to_owned())?;
        let token = format!("{TOKEN_PREFIX}{}", URL_SAFE_NO_PAD.encode(bytes));
        let now = self.time.elapsed();
        let wall = self.time.now_secs();
        let session = Session {
            user: user.to_owned(),
            opened,
            opened_at: wall,
            expires_at: wall + self.lifetime.as_secs(),
        };
        let mut held = self.held.lock().unwrap_or_else(PoisonError::into_inner);
        self.prune(&mut held, now);
        let mut mine: Vec<([u8; 32], u64)> = held
            .iter()
            .filter(|(_, held)| held.session.user == user)
            .map(|(key, held)| (*key, held.sequence))
            .collect();
        if mine.len() >= MAX_PER_USER {
            mine.sort_by_key(|(_, sequence)| *sequence);
            for (key, _) in mine.iter().take(mine.len() + 1 - MAX_PER_USER) {
                held.remove(key);
            }
        }
        if held.len() >= MAX_SESSIONS
            && let Some(oldest) = held
                .iter()
                .min_by_key(|(_, held)| (held.used, held.sequence))
                .map(|(key, _)| *key)
        {
            held.remove(&oldest);
        }
        held.insert(
            digest(&token),
            Held {
                session: session.clone(),
                started: now,
                used: now,
                sequence: self
                    .opened
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed),
            },
        );
        Ok((token, session))
    }

    /// The session `token` names, when it is live; its use moves its idle end.
    pub fn resolve(&self, token: &str) -> Option<Session> {
        if !token.starts_with(TOKEN_PREFIX) || token.len() > 128 {
            return None;
        }
        let now = self.time.elapsed();
        let key = digest(token);
        let mut held = self.held.lock().unwrap_or_else(PoisonError::into_inner);
        let live = held.get(&key).is_some_and(|held| self.live(held, now));
        if !live {
            held.remove(&key);
            return None;
        }
        let entry = held.get_mut(&key)?;
        entry.used = now;
        Some(entry.session.clone())
    }

    fn live(&self, held: &Held, now: Duration) -> bool {
        now.saturating_sub(held.started) < self.lifetime
            && now.saturating_sub(held.used) < self.idle
    }

    fn prune(&self, held: &mut HashMap<[u8; 32], Held>, now: Duration) {
        held.retain(|_, held| self.live(held, now));
    }

    /// Ends the session `token` names; whether there was one.
    pub fn end(&self, token: &str) -> bool {
        self.held
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&digest(token))
            .is_some()
    }

    /// Ends every session of `user`, but the one `keep` names; how many ended.
    pub fn end_user(&self, user: &str, keep: Option<&str>) -> usize {
        let keep = keep.map(digest);
        let mut held = self.held.lock().unwrap_or_else(PoisonError::into_inner);
        let before = held.len();
        held.retain(|key, held| held.session.user != user || Some(*key) == keep);
        before - held.len()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;
    use crate::time::{ManualClock, ManualMonotonic, TimeGuard};

    fn sessions() -> (Sessions, Arc<ManualMonotonic>) {
        let mono = Arc::new(ManualMonotonic::default());
        let time = Arc::new(TimeGuard::new(
            Arc::new(ManualClock::at(1_800_000_000)),
            mono.clone(),
            Duration::from_secs(30),
        ));
        (
            Sessions::new(Duration::from_secs(3_600), Duration::from_secs(600), time),
            mono,
        )
    }

    #[test]
    fn a_session_is_a_random_token_kept_as_its_digest_and_ends_idle_or_at_its_lifetime() {
        let (sessions, mono) = sessions();
        let (token, session) = sessions.open("alice", Opened::Password).expect("opened");
        assert!(
            token.starts_with(TOKEN_PREFIX) && token.len() == 4 + 43,
            "{token}"
        );
        assert_eq!(session.expires_at, 1_800_000_000 + 3_600);
        let (other, _) = sessions.open("alice", Opened::Password).expect("opened");
        assert_ne!(token, other);
        assert_eq!(sessions.resolve(&token).expect("live").user, "alice");
        assert!(sessions.resolve("pgs_forged").is_none());
        assert!(sessions.resolve("not-a-session").is_none());
        // Used every nine minutes, it outlives the idle time but not its lifetime.
        for _ in 0..6 {
            mono.advance(Duration::from_secs(540));
            assert!(sessions.resolve(&token).is_some());
        }
        mono.advance(Duration::from_secs(540));
        assert!(sessions.resolve(&token).is_none(), "past its lifetime");
        assert!(sessions.resolve(&other).is_none(), "idle too long");
    }

    #[test]
    fn sign_out_and_a_users_end_end_their_sessions_and_a_user_holds_a_bounded_number() {
        let (sessions, _) = sessions();
        let (first, _) = sessions.open("bob", Opened::Password).expect("opened");
        let (second, _) = sessions.open("bob", Opened::Password).expect("opened");
        let (carol, _) = sessions.open("carol", Opened::Password).expect("opened");
        assert!(sessions.end(&first));
        assert!(sessions.resolve(&first).is_none());
        assert_eq!(sessions.end_user("bob", Some(&second)), 0, "the one kept");
        assert_eq!(sessions.end_user("bob", None), 1);
        assert!(
            sessions.resolve(&carol).is_some(),
            "another user's untouched"
        );
        let tokens: Vec<String> = (0..MAX_PER_USER + 3)
            .map(|_| sessions.open("dave", Opened::Password).expect("opened").0)
            .collect();
        assert!(sessions.resolve(&tokens[0]).is_none(), "the oldest went");
        assert!(sessions.resolve(&tokens[MAX_PER_USER + 2]).is_some());
    }
}
