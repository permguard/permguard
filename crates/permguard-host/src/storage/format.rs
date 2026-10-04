// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The header every storage format begins with, and the whole-file codec.
//!
//! ```text
//! header (16 bytes, big-endian)      magic[8] | version u16 | mandatory flags u16 | reserved u32 = 0
//! whole file                         header | body length u64 | body | SHA-256(everything before)
//! ```
//!
//! A reader refuses — [`StorageError::Unsupported`] — another magic, a version newer than it reads,
//! a mandatory flag it does not know and a non-zero reserved field: a file written by a newer build
//! is never half-understood. A whole file whose length or checksum does not hold is
//! [`StorageError::Corruption`].

use sha2::{Digest as _, Sha256};

use super::{Result, StorageError};

/// The header's length.
pub const HEADER_LEN: usize = 16;

/// The checksum's length.
pub const CHECKSUM_LEN: usize = 32;

/// One format: its magic and the version this build writes, and the mandatory flags it knows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Format {
    pub magic: [u8; 8],
    pub version: u16,
    /// Every mandatory flag this build understands for the format.
    pub known_flags: u16,
}

impl Format {
    /// A format from one of the magics of `permguard_core::domains::magic`, which are exactly
    /// eight bytes; anything else does not compile.
    pub const fn new(magic: &str, version: u16, known_flags: u16) -> Self {
        let bytes = magic.as_bytes();
        assert!(bytes.len() == 8, "a format's magic is exactly eight bytes");
        let mut held = [0u8; 8];
        let mut index = 0;
        while index < 8 {
            held[index] = bytes[index];
            index += 1;
        }
        Self {
            magic: held,
            version,
            known_flags,
        }
    }

    fn name(&self) -> String {
        String::from_utf8_lossy(&self.magic)
            .trim_end_matches('\0')
            .to_owned()
    }
}

/// A journal segment, version 1.
pub const JOURNAL_SEGMENT: Format =
    Format::new(permguard_core::domains::magic::JOURNAL_SEGMENT, 1, 0);
/// A replaceable view, version 1.
pub const VIEW: Format = Format::new(permguard_core::domains::magic::VIEW, 1, 0);
/// A snapshot cache, version 1.
pub const SNAPSHOT: Format = Format::new(permguard_core::domains::magic::SNAPSHOT, 1, 0);
/// A tombstone, version 1.
pub const TOMBSTONE: Format = Format::new(permguard_core::domains::magic::TOMBSTONE, 1, 0);

/// A header read back.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    pub version: u16,
    pub flags: u16,
}

/// The header of `format`, with the mandatory `flags` this file uses.
pub fn header(format: Format, flags: u16) -> [u8; HEADER_LEN] {
    let mut bytes = [0u8; HEADER_LEN];
    bytes[..8].copy_from_slice(&format.magic);
    bytes[8..10].copy_from_slice(&format.version.to_be_bytes());
    bytes[10..12].copy_from_slice(&flags.to_be_bytes());
    bytes
}

/// Reads a header of `format`, refusing anything this build must not half-understand.
// conformance: boundary
pub fn read_header(bytes: &[u8], format: Format) -> Result<Header> {
    let Some(held) = bytes.get(..HEADER_LEN) else {
        return Err(StorageError::Corruption(format!(
            "a `{}` file shorter than its header",
            format.name()
        )));
    };
    if held[..8] != format.magic {
        return Err(StorageError::Unsupported(format!(
            "expected a `{}` file, found magic {:02x?}",
            format.name(),
            &held[..8]
        )));
    }
    let version = u16::from_be_bytes([held[8], held[9]]);
    let flags = u16::from_be_bytes([held[10], held[11]]);
    let reserved = u32::from_be_bytes([held[12], held[13], held[14], held[15]]);
    if version == 0 {
        return Err(StorageError::Corruption(format!(
            "`{}` version 0, which no build writes",
            format.name()
        )));
    }
    if version > format.version {
        return Err(StorageError::Unsupported(format!(
            "`{}` version {version}; this build reads up to {}",
            format.name(),
            format.version
        )));
    }
    if flags & !format.known_flags != 0 {
        return Err(StorageError::Unsupported(format!(
            "`{}` mandatory flags {flags:#06x}; this build knows {:#06x}",
            format.name(),
            format.known_flags
        )));
    }
    if reserved != 0 {
        return Err(StorageError::Unsupported(format!(
            "`{}` with a non-zero reserved field",
            format.name()
        )));
    }
    Ok(Header { version, flags })
}

/// SHA-256 of `bytes`.
pub fn checksum(bytes: &[u8]) -> [u8; CHECKSUM_LEN] {
    Sha256::digest(bytes).into()
}

/// A whole file of `format`: header, body length, body, checksum.
pub fn encode_file(format: Format, flags: u16, body: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(HEADER_LEN + 8 + body.len() + CHECKSUM_LEN);
    bytes.extend_from_slice(&header(format, flags));
    bytes.extend_from_slice(&(body.len() as u64).to_be_bytes());
    bytes.extend_from_slice(body);
    let sum = checksum(&bytes);
    bytes.extend_from_slice(&sum);
    bytes
}

/// The header and body of a whole file of `format`, verified.
// conformance: boundary
pub fn decode_file(bytes: &[u8], format: Format) -> Result<(Header, &[u8])> {
    let header = read_header(bytes, format)?;
    let corrupt =
        |what: &str| StorageError::Corruption(format!("a `{}` file {what}", format.name()));
    let length = bytes
        .get(HEADER_LEN..HEADER_LEN + 8)
        .and_then(|held| <[u8; 8]>::try_from(held).ok())
        .map(u64::from_be_bytes)
        .ok_or_else(|| corrupt("without a body length"))?;
    let length = usize::try_from(length).map_err(|_| corrupt("with an impossible length"))?;
    let body_end = (HEADER_LEN + 8)
        .checked_add(length)
        .ok_or_else(|| corrupt("with an impossible length"))?;
    if bytes.len() != body_end + CHECKSUM_LEN {
        return Err(corrupt("whose length does not match its body"));
    }
    if checksum(&bytes[..body_end]) != bytes[body_end..] {
        return Err(corrupt("whose checksum does not match"));
    }
    Ok((header, &bytes[HEADER_LEN + 8..body_end]))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;

    #[test]
    fn a_whole_file_round_trips_and_its_layout_is_the_decided_one() {
        let bytes = encode_file(VIEW, 0, b"body");
        assert_eq!(&bytes[..8], b"PGSVIEW\0");
        assert_eq!(
            &bytes[8..16],
            &[0, 1, 0, 0, 0, 0, 0, 0],
            "version 1, no flags, reserved 0"
        );
        assert_eq!(&bytes[16..24], &4u64.to_be_bytes());
        assert_eq!(&bytes[24..28], b"body");
        assert_eq!(bytes.len(), 16 + 8 + 4 + 32);
        let (header, body) = decode_file(&bytes, VIEW).expect("it decodes");
        assert_eq!(
            header,
            Header {
                version: 1,
                flags: 0
            }
        );
        assert_eq!(body, b"body");
    }

    #[test]
    fn what_this_build_must_not_half_understand_is_refused() {
        let good = encode_file(VIEW, 0, b"body");
        let refuse = |patch: &dyn Fn(&mut Vec<u8>)| {
            let mut bytes = good.clone();
            patch(&mut bytes);
            decode_file(&bytes, VIEW).expect_err("refused")
        };
        assert!(matches!(
            refuse(&|bytes| bytes[0] = b'X'),
            StorageError::Unsupported(_)
        ));
        assert!(
            matches!(refuse(&|bytes| bytes[9] = 2), StorageError::Unsupported(_)),
            "newer"
        );
        assert!(
            matches!(refuse(&|bytes| bytes[11] = 1), StorageError::Unsupported(_)),
            "a flag"
        );
        assert!(
            matches!(refuse(&|bytes| bytes[15] = 1), StorageError::Unsupported(_)),
            "reserved"
        );
        assert!(
            matches!(refuse(&|bytes| bytes[9] = 0), StorageError::Corruption(_)),
            "version 0 is damage, not a newer build"
        );
        assert!(
            matches!(refuse(&|bytes| bytes[25] ^= 1), StorageError::Corruption(_)),
            "a bit"
        );
        assert!(
            matches!(
                refuse(&|bytes| {
                    bytes.pop();
                }),
                StorageError::Corruption(_)
            ),
            "short"
        );
        assert!(matches!(
            decode_file(&good, SNAPSHOT).expect_err("another format"),
            StorageError::Unsupported(_)
        ));
    }
}
