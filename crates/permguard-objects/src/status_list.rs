// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The token status list's codec (iteration 02, WP-11.5, `2-security/9` The list), with the
//! structure of `draft-ietf-oauth-status-list-21`: each entry `bits` wide, packed from the least
//! significant bits of each byte, the bytes compressed with DEFLATE in the ZLIB format at the
//! highest level, then base64url without padding.
//!
//! The IAM Host encodes; a member decodes, bounded before and during decompression, never after:
//! a list that would decompress past what its entries can take is refused while it is read.

use std::io::{Read as _, Write as _};

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use flate2::Compression;
use flate2::read::ZlibDecoder;
use flate2::write::ZlibEncoder;

/// The entries of every list the IAM Host opens: `2^20`.
pub const ENTRIES: usize = 1 << 20;

/// Why a list was not encoded or decoded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StatusListError {
    /// `bits` is not 1, 2, 4 or 8.
    Bits(u8),
    /// An index past the list's entries.
    Index(usize),
    /// A value wider than `bits`.
    Value(u8),
    /// The encoded list is not base64url, ZLIB, or the size its entries take.
    Encoding(String),
    /// The encoded or decompressed list is larger than the reader allows.
    TooLarge(usize),
}

impl std::fmt::Display for StatusListError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Bits(bits) => write!(f, "{bits} bits per entry: a list takes 1, 2, 4 or 8"),
            Self::Index(index) => write!(f, "index {index} is past the list's entries"),
            Self::Value(value) => write!(f, "{value} does not fit the list's entries"),
            Self::Encoding(detail) => write!(f, "the list is not encoded as one: {detail}"),
            Self::TooLarge(bytes) => write!(f, "the list takes {bytes} bytes, past its bound"),
        }
    }
}

impl std::error::Error for StatusListError {}

/// A status list: `bits` per entry, every entry 0 until written.
#[derive(Clone, PartialEq, Eq)]
pub struct StatusList {
    bits: u8,
    bytes: Vec<u8>,
}

impl std::fmt::Debug for StatusList {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StatusList")
            .field("bits", &self.bits)
            .field("entries", &self.len())
            .finish()
    }
}

fn checked_bits(bits: u8) -> Result<u8, StatusListError> {
    if matches!(bits, 1 | 2 | 4 | 8) {
        Ok(bits)
    } else {
        Err(StatusListError::Bits(bits))
    }
}

impl StatusList {
    /// A list of `entries` entries of `bits` each, every one 0. `entries` is rounded up to
    /// whole bytes.
    pub fn new(bits: u8, entries: usize) -> Result<Self, StatusListError> {
        let bits = checked_bits(bits)?;
        let per_byte = usize::from(8 / bits);
        Ok(Self {
            bits,
            bytes: vec![0; entries.div_ceil(per_byte)],
        })
    }

    /// Bits per entry.
    pub fn bits(&self) -> u8 {
        self.bits
    }

    /// The number of entries.
    pub fn len(&self) -> usize {
        self.bytes.len() * usize::from(8 / self.bits)
    }

    /// Whether the list holds no entry.
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    fn place(&self, index: usize) -> Result<(usize, u32, u8), StatusListError> {
        let per_byte = usize::from(8 / self.bits);
        if index >= self.len() {
            return Err(StatusListError::Index(index));
        }
        let shift = u32::try_from(index % per_byte).unwrap_or(0) * u32::from(self.bits);
        let mask = if self.bits == 8 {
            0xff
        } else {
            (1u8 << self.bits) - 1
        };
        Ok((index / per_byte, shift, mask))
    }

    /// The entry at `index`.
    pub fn get(&self, index: usize) -> Result<u8, StatusListError> {
        let (byte, shift, mask) = self.place(index)?;
        Ok((self.bytes[byte] >> shift) & mask)
    }

    /// Writes `value` at `index`.
    pub fn set(&mut self, index: usize, value: u8) -> Result<(), StatusListError> {
        let (byte, shift, mask) = self.place(index)?;
        if value & !mask != 0 {
            return Err(StatusListError::Value(value));
        }
        self.bytes[byte] = (self.bytes[byte] & !(mask << shift)) | (value << shift);
        Ok(())
    }

    /// The list's `lst`: ZLIB at the highest level, base64url without padding.
    pub fn encode(&self) -> Result<String, StatusListError> {
        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::best());
        encoder
            .write_all(&self.bytes)
            .map_err(|error| StatusListError::Encoding(error.to_string()))?;
        let compressed = encoder
            .finish()
            .map_err(|error| StatusListError::Encoding(error.to_string()))?;
        Ok(URL_SAFE_NO_PAD.encode(compressed))
    }

    /// Reads a list of `bits` from its `lst`, refusing an encoded form past `max_encoded` bytes
    /// before it is decoded and a list past `max_entries` while it decompresses.
    pub fn decode(
        bits: u8,
        lst: &str,
        max_encoded: usize,
        max_entries: usize,
    ) -> Result<Self, StatusListError> {
        let bits = checked_bits(bits)?;
        if lst.len() > max_encoded {
            return Err(StatusListError::TooLarge(lst.len()));
        }
        let compressed = URL_SAFE_NO_PAD
            .decode(lst)
            .map_err(|error| StatusListError::Encoding(error.to_string()))?;
        let max_bytes = max_entries.div_ceil(usize::from(8 / bits));
        // One byte past the bound is read, so a list that is too large is seen as such.
        let mut bytes = Vec::new();
        ZlibDecoder::new(compressed.as_slice())
            .take(
                u64::try_from(max_bytes)
                    .unwrap_or(u64::MAX)
                    .saturating_add(1),
            )
            .read_to_end(&mut bytes)
            .map_err(|error| StatusListError::Encoding(error.to_string()))?;
        if bytes.len() > max_bytes {
            return Err(StatusListError::TooLarge(bytes.len()));
        }
        if bytes.is_empty() {
            return Err(StatusListError::Encoding(
                "the list holds no entry".to_owned(),
            ));
        }
        Ok(Self { bits, bytes })
    }
}
