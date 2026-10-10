// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The session's messages, byte for byte (owner decisions of 2026-10-08;
//! `contracts/cbor/session.json`).
//!
//! | Message      | Shape                                                                                                  |
//! | ------------ | ------------------------------------------------------------------------------------------------------ |
//! | presentation | {1 identity document, 2 [succession records], 3 epoch-1 public key}: what `GET /host/v1/identity` answers |
//! | `hello`      | {1 version, 2 host, 3 epoch, 4 declared_assurance, 5 nonce, 6 operation, 7? membership_id, 8? task}   |
//! | `challenge`  | {1 host, 2 epoch, 3 declared_assurance, 4 nonce, 5 expires}                                            |
//! | transcript   | {1 protocol, 2 initiator_host, 3 responder_host, 4 initiator_epoch, 5 responder_epoch, 6 nonce_A, 7 nonce_B, 8? membership_id, 9? task, 10 operation, 11 expires_at, 12 tls_exporter, 13 hello_digest, 14 challenge_digest, 15 signer} |
//!
//! Every map is closed and canonical; an absent optional member is omitted, never null. Hosts are
//! 16-byte UUIDv7 values, nonces 16 bytes from the OS CSPRNG, the exporter 32 bytes. `hello_digest`
//! and `challenge_digest` are taken over the exact bytes received, under their own domains. A
//! proof is a COSE_Sign1 `permguard.host.proof.v1` over the transcript, signed by the identity
//! key of the epoch the transcript names for its signer.

use std::fmt;
use std::str::FromStr;

use permguard_core::assurance::AssuranceProfile;
use permguard_core::domains::digest::{HOST_SESSION_CHALLENGE, HOST_SESSION_HELLO};
use permguard_core::domains::protected::HOST_SESSION;
use permguard_objects::cbor::Value;
use permguard_objects::digest::Digest;

use crate::identity::record::{Labelled, RecordError, encode, is_uuid_v7, uint};

/// The `hello` version this build speaks.
pub const VERSION: u64 = 1;
/// Nonce length: 128 random bits.
pub const NONCE_BYTES: usize = 16;
/// The RFC 9266 `tls-exporter` length.
pub const EXPORTER_BYTES: usize = 32;
/// The longest `membership_id` or `task` a message carries.
pub const MAX_NAME_BYTES: usize = 128;
/// The largest frame the channel reads: a presentation with a long succession chain fits.
pub const MAX_FRAME_BYTES: usize = 512 * 1024;

/// What a session is opened for: a closed registry (owner decision of 2026-10-08).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Operation {
    /// A member asks to join a membership (WP-11).
    Enroll,
    /// A member runs a task of its membership (WP-11).
    Task,
    /// A member asks its coordinator for the manifests of its membership, or for its revocation
    /// (WP-4.1, owner decision of 2026-10-09).
    Membership,
}

impl Operation {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Enroll => "enroll",
            Self::Task => "task",
            Self::Membership => "membership",
        }
    }
}

impl FromStr for Operation {
    type Err = RecordError;

    fn from_str(value: &str) -> Result<Self, RecordError> {
        match value {
            "enroll" => Ok(Self::Enroll),
            "task" => Ok(Self::Task),
            "membership" => Ok(Self::Membership),
            _ => Err(RecordError("not a session operation".to_owned())),
        }
    }
}

/// Which side of a session a proof is signed by.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Initiator,
    Responder,
}

impl Role {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Initiator => "initiator",
            Self::Responder => "responder",
        }
    }
}

impl FromStr for Role {
    type Err = RecordError;

    fn from_str(value: &str) -> Result<Self, RecordError> {
        match value {
            "initiator" => Ok(Self::Initiator),
            "responder" => Ok(Self::Responder),
            _ => Err(RecordError("not a session role".to_owned())),
        }
    }
}

/// A Host's published identity, as the channel carries it before `hello`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Presentation {
    pub document: Vec<u8>,
    pub successions: Vec<Vec<u8>>,
    pub first_public_key: Vec<u8>,
}

impl Presentation {
    pub fn encode(&self) -> Result<Vec<u8>, RecordError> {
        encode(vec![
            (Value::Int(1), Value::Bytes(self.document.clone())),
            (
                Value::Int(2),
                Value::Array(
                    self.successions
                        .iter()
                        .map(|record| Value::Bytes(record.clone()))
                        .collect(),
                ),
            ),
            (Value::Int(3), Value::Bytes(self.first_public_key.clone())),
        ])
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, RecordError> {
        bounded(bytes)?;
        let mut map = Labelled::read(bytes, "a presentation")?;
        let presentation = Self {
            document: map.bytes(1)?,
            successions: map.byte_strings(2)?,
            first_public_key: map.bytes(3)?,
        };
        map.finish()?;
        Ok(presentation)
    }
}

/// The initiator's opening message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hello {
    pub version: u64,
    pub host: [u8; 16],
    pub epoch: u64,
    pub declared_assurance: AssuranceProfile,
    pub nonce: [u8; NONCE_BYTES],
    pub operation: Operation,
    pub membership_id: Option<String>,
    pub task: Option<String>,
    /// The digest of the one request the session serves, for `enroll` and `membership`
    /// (WP-4.1, owner decision of 2026-10-09): signed by the transcript as member 16.
    pub request_digest: Option<Digest>,
}

impl Hello {
    pub fn encode(&self) -> Result<Vec<u8>, RecordError> {
        let mut pairs = vec![
            (Value::Int(1), uint(self.version)?),
            (Value::Int(2), Value::Bytes(self.host.to_vec())),
            (Value::Int(3), uint(self.epoch)?),
            (
                Value::Int(4),
                Value::Text(self.declared_assurance.as_str().to_owned()),
            ),
            (Value::Int(5), Value::Bytes(self.nonce.to_vec())),
            (
                Value::Int(6),
                Value::Text(self.operation.as_str().to_owned()),
            ),
        ];
        if let Some(membership_id) = &self.membership_id {
            pairs.push((Value::Int(7), Value::Text(membership_id.clone())));
        }
        if let Some(task) = &self.task {
            pairs.push((Value::Int(8), Value::Text(task.clone())));
        }
        if let Some(digest) = &self.request_digest {
            pairs.push((Value::Int(9), Value::Text(digest.to_string())));
        }
        encode(pairs)
    }

    /// Reads a `hello`: a version this build does not speak, a host that is not a UUIDv7, an
    /// epoch 0, an unknown profile or operation, or a name beyond its bound is refused here.
    pub fn decode(bytes: &[u8]) -> Result<Self, RecordError> {
        bounded(bytes)?;
        let mut map = Labelled::read(bytes, "a hello")?;
        let hello = Self {
            version: map.uint(1)?,
            host: map.id(2)?,
            epoch: map.uint(3)?,
            declared_assurance: profile(&map.text(4)?)?,
            nonce: map.fixed(5)?,
            operation: map.text(6)?.parse()?,
            membership_id: map.optional_text(7)?,
            task: map.optional_text(8)?,
            request_digest: map.optional_digest(9)?,
        };
        map.finish()?;
        if hello.version != VERSION {
            return Err(RecordError(format!(
                "hello version {} is not {VERSION}",
                hello.version
            )));
        }
        host_and_epoch(&hello.host, hello.epoch)?;
        names(hello.membership_id.as_deref(), hello.task.as_deref())?;
        Ok(hello)
    }
}

/// The responder's answer to `hello`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Challenge {
    pub host: [u8; 16],
    pub epoch: u64,
    pub declared_assurance: AssuranceProfile,
    pub nonce: [u8; NONCE_BYTES],
    /// Unix seconds after which the responder accepts no proof for this nonce.
    pub expires: u64,
}

impl Challenge {
    pub fn encode(&self) -> Result<Vec<u8>, RecordError> {
        encode(vec![
            (Value::Int(1), Value::Bytes(self.host.to_vec())),
            (Value::Int(2), uint(self.epoch)?),
            (
                Value::Int(3),
                Value::Text(self.declared_assurance.as_str().to_owned()),
            ),
            (Value::Int(4), Value::Bytes(self.nonce.to_vec())),
            (Value::Int(5), uint(self.expires)?),
        ])
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, RecordError> {
        bounded(bytes)?;
        let mut map = Labelled::read(bytes, "a challenge")?;
        let challenge = Self {
            host: map.id(1)?,
            epoch: map.uint(2)?,
            declared_assurance: profile(&map.text(3)?)?,
            nonce: map.fixed(4)?,
            expires: map.uint(5)?,
        };
        map.finish()?;
        host_and_epoch(&challenge.host, challenge.epoch)?;
        Ok(challenge)
    }
}

/// What each proof signs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Transcript {
    pub initiator_host: [u8; 16],
    pub responder_host: [u8; 16],
    pub initiator_epoch: u64,
    pub responder_epoch: u64,
    pub nonce_a: [u8; NONCE_BYTES],
    pub nonce_b: [u8; NONCE_BYTES],
    pub membership_id: Option<String>,
    pub task: Option<String>,
    pub operation: Operation,
    pub expires_at: u64,
    pub tls_exporter: [u8; EXPORTER_BYTES],
    pub hello_digest: Digest,
    pub challenge_digest: Digest,
    pub signer: Role,
    /// The digest of the session's one request, for `enroll` and `membership` (WP-4.1).
    pub request_digest: Option<Digest>,
}

impl Transcript {
    pub fn encode(&self) -> Result<Vec<u8>, RecordError> {
        let mut pairs = vec![
            (Value::Int(1), Value::Text(HOST_SESSION.to_owned())),
            (Value::Int(2), Value::Bytes(self.initiator_host.to_vec())),
            (Value::Int(3), Value::Bytes(self.responder_host.to_vec())),
            (Value::Int(4), uint(self.initiator_epoch)?),
            (Value::Int(5), uint(self.responder_epoch)?),
            (Value::Int(6), Value::Bytes(self.nonce_a.to_vec())),
            (Value::Int(7), Value::Bytes(self.nonce_b.to_vec())),
        ];
        if let Some(membership_id) = &self.membership_id {
            pairs.push((Value::Int(8), Value::Text(membership_id.clone())));
        }
        if let Some(task) = &self.task {
            pairs.push((Value::Int(9), Value::Text(task.clone())));
        }
        pairs.extend([
            (
                Value::Int(10),
                Value::Text(self.operation.as_str().to_owned()),
            ),
            (Value::Int(11), uint(self.expires_at)?),
            (Value::Int(12), Value::Bytes(self.tls_exporter.to_vec())),
            (Value::Int(13), Value::Text(self.hello_digest.to_string())),
            (
                Value::Int(14),
                Value::Text(self.challenge_digest.to_string()),
            ),
            (Value::Int(15), Value::Text(self.signer.as_str().to_owned())),
        ]);
        if let Some(digest) = &self.request_digest {
            pairs.push((Value::Int(16), Value::Text(digest.to_string())));
        }
        encode(pairs)
    }

    /// Reads a transcript: for the vectors and for diagnosing a refused proof. A verifier never
    /// trusts a decoded transcript; it compares the signed bytes with the ones it built.
    pub fn decode(bytes: &[u8]) -> Result<Self, RecordError> {
        bounded(bytes)?;
        let mut map = Labelled::read(bytes, "a transcript")?;
        let protocol = map.text(1)?;
        let transcript = Self {
            initiator_host: map.id(2)?,
            responder_host: map.id(3)?,
            initiator_epoch: map.uint(4)?,
            responder_epoch: map.uint(5)?,
            nonce_a: map.fixed(6)?,
            nonce_b: map.fixed(7)?,
            membership_id: map.optional_text(8)?,
            task: map.optional_text(9)?,
            operation: map.text(10)?.parse()?,
            expires_at: map.uint(11)?,
            tls_exporter: map.fixed(12)?,
            hello_digest: map.digest(13)?,
            challenge_digest: map.digest(14)?,
            signer: map.text(15)?.parse()?,
            request_digest: map.optional_digest(16)?,
        };
        map.finish()?;
        if protocol != HOST_SESSION {
            return Err(RecordError(format!("`{protocol}` is not {HOST_SESSION}")));
        }
        Ok(transcript)
    }
}

/// The digest a transcript cites a `hello` by: over the bytes received.
pub fn hello_digest(bytes: &[u8]) -> Digest {
    let mut input = HOST_SESSION_HELLO.as_bytes().to_vec();
    input.extend_from_slice(bytes);
    Digest::compute(&input)
}

/// The digest a transcript cites a `challenge` by: over the bytes received.
pub fn challenge_digest(bytes: &[u8]) -> Digest {
    let mut input = HOST_SESSION_CHALLENGE.as_bytes().to_vec();
    input.extend_from_slice(bytes);
    Digest::compute(&input)
}

fn bounded(bytes: &[u8]) -> Result<(), RecordError> {
    if bytes.len() > MAX_FRAME_BYTES {
        return Err(RecordError(format!(
            "a session message of {} bytes, beyond {MAX_FRAME_BYTES}",
            bytes.len()
        )));
    }
    Ok(())
}

fn profile(name: &str) -> Result<AssuranceProfile, RecordError> {
    name.parse()
        .map_err(|_| RecordError("not an assurance profile".to_owned()))
}

fn host_and_epoch(host: &[u8; 16], epoch: u64) -> Result<(), RecordError> {
    if !is_uuid_v7(host) {
        return Err(RecordError(
            "a session names a Host id that is not a UUIDv7".to_owned(),
        ));
    }
    if epoch == 0 {
        return Err(RecordError("identity epochs start at 1".to_owned()));
    }
    Ok(())
}

fn names(membership_id: Option<&str>, task: Option<&str>) -> Result<(), RecordError> {
    for name in [membership_id, task].into_iter().flatten() {
        if name.is_empty() || name.len() > MAX_NAME_BYTES {
            return Err(RecordError(format!(
                "a membership id or task is 1 to {MAX_NAME_BYTES} bytes"
            )));
        }
    }
    Ok(())
}

impl fmt::Display for Operation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests;
