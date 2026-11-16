// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! What a call that did not produce what was asked for says: the shape every surface answers with.

/// A call that did not produce what was asked for, and why.
#[derive(Debug)]
pub struct Failure {
    /// The closed category, exactly as the server named it — or the transport's own.
    pub class: String,
    /// The stable code: the server's, or the transport's.
    pub reason: String,
    /// The sentence.
    pub detail: String,
    /// Whether the mistake is in what was asked (a usage error) or in the world (a failure).
    pub usage: bool,
}

impl std::fmt::Display for Failure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.detail)
    }
}
