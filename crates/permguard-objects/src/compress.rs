// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! Object compression: zlib (RFC 1950), the algorithm git uses for loose
//! objects. Two places use it, both through this module so they cannot
//! drift: objects at rest (both stores), and NOTP batches when the two
//! sides negotiated it.
//!
//! Digests are always computed over the uncompressed canonical bytes —
//! compression is an encoding of the shelf and the pipe, never of the
//! identity. Decompression is capped: input claiming to inflate past the
//! caller's bound is refused, so a hostile stream cannot balloon memory.

use std::io::Read as _;

use flate2::Compression;
use flate2::bufread::{ZlibDecoder, ZlibEncoder};

/// The negotiated wire name of the one algorithm this version speaks.
/// Additive forever: a future algorithm is a new name, never a new meaning.
pub const DEFLATE: &str = "deflate";

/// Why decompression refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CompressError {
    /// The stream is not valid zlib data.
    Malformed(String),
    /// The stream inflates past the caller's bound: refused, not buffered.
    TooLarge { limit: usize },
}

impl std::fmt::Display for CompressError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CompressError::Malformed(detail) => write!(f, "not a zlib stream: {detail}"),
            CompressError::TooLarge { limit } => {
                write!(f, "inflates past the {limit}-byte bound")
            }
        }
    }
}

impl std::error::Error for CompressError {}

/// Compresses bytes with zlib at the default level — the balance git ships.
pub fn deflate(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    // Reading from an encoder over a slice cannot fail.
    let _ = ZlibEncoder::new(bytes, Compression::default()).read_to_end(&mut out);
    out
}

/// Decompresses a zlib stream, refusing anything that inflates past `limit`.
pub fn inflate(bytes: &[u8], limit: usize) -> Result<Vec<u8>, CompressError> {
    let mut out = Vec::new();
    let mut decoder = ZlibDecoder::new(bytes).take(limit as u64 + 1);
    decoder
        .read_to_end(&mut out)
        .map_err(|error| CompressError::Malformed(error.to_string()))?;
    if out.len() > limit {
        return Err(CompressError::TooLarge { limit });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_and_shrinks_text() {
        let text = "permit(principal, action, resource);\n".repeat(100);
        let packed = deflate(text.as_bytes());
        assert!(packed.len() < text.len());
        assert_eq!(inflate(&packed, text.len()).unwrap(), text.as_bytes());
    }

    #[test]
    fn empty_round_trips() {
        assert_eq!(inflate(&deflate(b""), 0).unwrap(), b"");
    }

    #[test]
    fn oversized_streams_are_refused_not_buffered() {
        let bomb = deflate(&vec![0u8; 1024 * 1024]);
        assert_eq!(
            inflate(&bomb, 1024),
            Err(CompressError::TooLarge { limit: 1024 })
        );
    }

    #[test]
    fn garbage_is_refused() {
        assert!(matches!(
            inflate(b"not zlib", 1024),
            Err(CompressError::Malformed(_))
        ));
    }
}
