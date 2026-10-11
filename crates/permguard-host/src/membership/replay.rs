// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The idempotency and replay gate of a coordinator's task messages (WP-4.4; owner decision of
//! 2026-10-11).
//!
//! ```text
//! host/members/replay/<membership_id>/<task_id>/
//! └── 0000.cbor … 1023.cbor     one answered request per slot, the slot `seq` modulo the window
//! ```
//!
//! The last [`WINDOW`] requests a task answered are kept with the digest of their message, taken
//! with the session's resource, and the answer. An identical repeat, a restart included, is
//! answered the stored answer without reaching the handler; the same request id with another
//! message, or while the first is still being answered, is refused `request_id_reused`. A request
//! older than the window is not remembered. Only the index is held in memory; an answer is read
//! back from its slot when a repeat asks for it. A temporary a crash left is swept, and a slot
//! that does not read is skipped and logged rather than closing the task.

use std::collections::{BTreeMap, BTreeSet};

use sha2::{Digest as _, Sha256};

use super::record::ReplayEntry;
use super::{MembershipError, Store, hex};
use crate::storage::dir::{Dir, TEMP_PREFIX};
use crate::storage::format;
use crate::storage::write::{read_view, replace_view};

/// The directory below `host/members/`.
pub const DIRECTORY: &str = "replay";
/// How many answered requests a task keeps (owner decision).
pub const WINDOW: u64 = 1024;

/// What the gate says of a message.
pub enum Gate<'a> {
    /// Not seen inside the window: the handler answers it, and [`Store::remember`] keeps the
    /// answer under the reservation. Dropped unkept, the reservation frees the id.
    New(Reservation<'a>),
    /// An identical repeat: its stored answer.
    Replay(Vec<u8>),
    /// The request id answered another message, or is being answered.
    Reused,
}

impl std::fmt::Debug for Gate<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::New(_) => f.write_str("New"),
            Self::Replay(answer) => f.debug_tuple("Replay").field(answer).finish(),
            Self::Reused => f.write_str("Reused"),
        }
    }
}

/// A request id held while its handler answers: a concurrent same id is refused.
pub struct Reservation<'a> {
    store: &'a Store,
    key: ([u8; 16], String),
    request_id: String,
    digest: [u8; 32],
}

impl Drop for Reservation<'_> {
    fn drop(&mut self) {
        if let Some(window) = self
            .store
            .windows
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get_mut(&self.key)
        {
            window.in_flight.remove(&self.request_id);
        }
    }
}

/// One task's window, as read from its slots.
#[derive(Debug, Default)]
pub(super) struct Window {
    next_seq: u64,
    /// By request id: its sequence number and its message's digest.
    by_request: BTreeMap<String, (u64, [u8; 32])>,
    /// The ids whose handler is answering now.
    in_flight: BTreeSet<String>,
}

/// SHA-256 of a task message's bytes and the session's resource: what the gate compares a repeat
/// by, so an answer given over one resource is never served over another.
pub fn message_digest(bytes: &[u8], resource: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hasher.update(resource.as_bytes());
    hasher.finalize().into()
}

fn slot(seq: u64) -> String {
    format!("{:04}.cbor", seq % WINDOW)
}

impl Store {
    fn window_dir(&self, id: &[u8; 16], task_id: &str) -> Result<Dir, MembershipError> {
        Ok(self
            .dir
            .subdir(DIRECTORY, true)?
            .subdir(&hex(id), true)?
            .subdir(task_id, true)?)
    }

    /// Reads `task_id`'s window of `id` from its slots: a temporary is swept, a slot that does not
    /// read is skipped.
    fn read_window(&self, id: &[u8; 16], task_id: &str) -> Result<Window, MembershipError> {
        let dir = self.window_dir(id, task_id)?;
        dir.sweep_temps()?;
        let mut window = Window::default();
        for name in dir.names()? {
            if name.starts_with(TEMP_PREFIX) {
                continue;
            }
            let entry = match read_view(&dir, &name, format::VIEW)
                .map_err(MembershipError::from)
                .and_then(|bytes| {
                    let bytes = bytes.ok_or_else(|| {
                        MembershipError::Storage("the slot went missing".to_owned())
                    })?;
                    Ok(ReplayEntry::decode(&bytes)?)
                }) {
                Ok(entry) if entry.task_id == task_id && name == slot(entry.seq) => entry,
                Ok(_) => {
                    unreadable(&name, "another task's or another slot's entry");
                    continue;
                }
                Err(error) => {
                    unreadable(&name, &error.to_string());
                    continue;
                }
            };
            window.next_seq = window.next_seq.max(entry.seq.saturating_add(1));
            window
                .by_request
                .insert(entry.request_id, (entry.seq, entry.message_digest));
        }
        // A slot rewritten since keeps only its newest entry; anything older than the window is
        // forgotten.
        let floor = window.next_seq.saturating_sub(WINDOW);
        window.by_request.retain(|_, (seq, _)| *seq >= floor);
        Ok(window)
    }

    /// What the gate says of `request_id` of `task_id` of `id`, whose message digests to
    /// `digest`; a new one is reserved until it is remembered or the reservation dropped.
    pub fn gate(
        &self,
        id: &[u8; 16],
        task_id: &str,
        request_id: &str,
        digest: &[u8; 32],
    ) -> Result<Gate<'_>, MembershipError> {
        let mut windows = self
            .windows
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let key = (*id, task_id.to_owned());
        if !windows.contains_key(&key) {
            let read = self.read_window(id, task_id)?;
            windows.insert(key.clone(), read);
        }
        let window = windows
            .get_mut(&key)
            .ok_or_else(|| MembershipError::Storage("the replay window".to_owned()))?;
        if window.in_flight.contains(request_id) {
            return Ok(Gate::Reused);
        }
        let Some((seq, held)) = window.by_request.get(request_id).copied() else {
            window.in_flight.insert(request_id.to_owned());
            return Ok(Gate::New(Reservation {
                store: self,
                key,
                request_id: request_id.to_owned(),
                digest: *digest,
            }));
        };
        drop(windows);
        if held != *digest {
            return Ok(Gate::Reused);
        }
        let dir = self.window_dir(id, task_id)?;
        let bytes = read_view(&dir, &slot(seq), format::VIEW)?
            .ok_or_else(|| MembershipError::Storage("a replay slot went missing".to_owned()))?;
        let entry = ReplayEntry::decode(&bytes)?;
        if entry.request_id != request_id || entry.message_digest != *digest {
            return Err(MembershipError::Storage(
                "a replay slot holds another request than its index".to_owned(),
            ));
        }
        Ok(Gate::Replay(entry.answer))
    }

    /// Keeps `answer` to the request `reservation` holds, durably, in the next slot.
    pub fn remember(
        &self,
        reservation: Reservation<'_>,
        answer: &[u8],
    ) -> Result<(), MembershipError> {
        let mut windows = self
            .windows
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let (id, task_id) = &reservation.key;
        let window = windows
            .get_mut(&reservation.key)
            .ok_or_else(|| MembershipError::Storage("the replay window".to_owned()))?;
        let seq = window.next_seq;
        let entry = ReplayEntry {
            task_id: task_id.clone(),
            request_id: reservation.request_id.clone(),
            message_digest: reservation.digest,
            answer: answer.to_vec(),
            seq,
        };
        replace_view(
            &self.window_dir(id, task_id)?,
            &slot(seq),
            format::VIEW,
            &entry.encode()?,
        )?;
        window.next_seq = seq.saturating_add(1);
        // The entry this slot held leaves the window.
        let floor = window.next_seq.saturating_sub(WINDOW);
        window.by_request.retain(|_, (held, _)| *held >= floor);
        window
            .by_request
            .insert(reservation.request_id.clone(), (seq, reservation.digest));
        window.in_flight.remove(&reservation.request_id);
        drop(windows);
        Ok(())
    }
}

fn unreadable(name: &str, detail: &str) {
    tracing::warn!(
        event.name = "host.membership.replay_slot_unreadable",
        component = "host",
        slot = name,
        detail = detail,
        "a replay slot does not read: skipped, its request no longer remembered"
    );
}
