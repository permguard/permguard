// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The one text form of bytes every crate prints: lowercase hexadecimal, two characters a byte,
//! what a digest, a key id or a fingerprint looks like in a record, a log line and a file.

/// `bytes` as lowercase hexadecimal, two characters a byte.
pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::hex;

    #[test]
    fn two_characters_a_byte_lowercase() {
        assert_eq!(hex(&[]), "");
        assert_eq!(hex(&[0x00, 0x0a, 0xff]), "000aff");
    }
}
