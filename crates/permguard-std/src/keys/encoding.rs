// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The two base64 alphabets this crate has to write, and nothing else.
//!
//! A JWK carries the key in base64url without padding, because a key ends up in URLs and in JSON
//! that people paste. A PEM file carries it in standard base64 with padding and a line break every
//! sixty-four characters, because that is what every other tool on the machine will open it with.
//!
//! Written out rather than depended on: encoding is twenty lines with an exact specification and an
//! official set of test vectors, and RFC 4648 has not moved since 2006.

/// The alphabet RFC 4648 §4 defines — what PEM bodies are written in.
const STANDARD: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// The alphabet RFC 4648 §5 defines — what a JWK is written in.
const URL_SAFE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// How many characters a PEM body puts on a line.
const PEM_WIDTH: usize = 64;

/// Encodes `input` the way a JWK expects: URL-safe, and without the padding.
pub fn base64url(input: &[u8]) -> String {
    encode(input, URL_SAFE, false)
}

/// Encodes `input` the way a PEM body expects: standard alphabet, padded.
pub fn base64(input: &[u8]) -> String {
    encode(input, STANDARD, true)
}

/// Wraps DER key material in the PEM armour every other tool on the machine reads.
pub fn pem(label: &str, der: &[u8]) -> String {
    let body = base64(der);
    let mut out = format!("-----BEGIN {label}-----\n");

    for line in body.as_bytes().chunks(PEM_WIDTH) {
        out.push_str(&String::from_utf8_lossy(line));
        out.push('\n');
    }

    out.push_str(&format!("-----END {label}-----\n"));

    out
}

/// Reads what a JWK carries: URL-safe, unpadded.
pub fn from_base64url(input: &str) -> Option<Vec<u8>> {
    decode_with(input, URL_SAFE)
}

/// Reads back what [`pem`] wrote, ignoring the armour and any line breaks inside it.
pub fn from_pem(text: &str) -> Option<Vec<u8>> {
    let body: String = text
        .lines()
        .filter(|line| !line.starts_with("-----"))
        .flat_map(str::chars)
        .filter(|character| !character.is_whitespace())
        .collect();

    decode(&body)
}

fn encode(input: &[u8], alphabet: &[u8; 64], pad: bool) -> String {
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);

    for chunk in input.chunks(3) {
        let bits = (u32::from(chunk[0]) << 16)
            | (u32::from(chunk.get(1).copied().unwrap_or(0)) << 8)
            | u32::from(chunk.get(2).copied().unwrap_or(0));

        // Every chunk yields one character per six bits it actually carries, plus one for the
        // remainder: three bytes make four characters, two make three, one makes two.
        let characters = chunk.len() + 1;

        for index in 0..characters {
            let shift = 18 - 6 * index;
            let sextet = ((bits >> shift) & 0b11_1111) as usize;

            out.push(char::from(alphabet[sextet]));
        }

        if pad {
            for _ in characters..4 {
                out.push('=');
            }
        }
    }

    out
}

/// Decodes standard base64, tolerating the absence of padding.
fn decode(input: &str) -> Option<Vec<u8>> {
    decode_with(input, STANDARD)
}

/// Decodes against `alphabet`, tolerating the absence of padding.
fn decode_with(input: &str, alphabet: &[u8; 64]) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(input.len() / 4 * 3);
    let mut accumulator: u32 = 0;
    let mut bits = 0_u32;

    for character in input.chars() {
        if character == '=' {
            break;
        }

        let value = alphabet
            .iter()
            .position(|entry| *entry == character as u8)?;

        accumulator = (accumulator << 6) | value as u32;
        bits += 6;

        if bits >= 8 {
            bits -= 8;
            out.push(((accumulator >> bits) & 0xff) as u8);
        }
    }

    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The vectors in RFC 4648 §10, which is the whole reason this is worth writing by hand.
    #[test]
    fn test_the_published_vectors_encode_as_published() {
        for (input, expected) in [
            ("", ""),
            ("f", "Zg=="),
            ("fo", "Zm8="),
            ("foo", "Zm9v"),
            ("foob", "Zm9vYg=="),
            ("fooba", "Zm9vYmE="),
            ("foobar", "Zm9vYmFy"),
        ] {
            assert_eq!(base64(input.as_bytes()), expected, "encoding {input:?}");
        }
    }

    #[test]
    fn test_the_url_alphabet_drops_the_padding_and_the_two_characters_that_need_escaping() {
        // 0xfb 0xff encodes to the two characters the two alphabets disagree about.
        assert_eq!(base64(&[0xfb, 0xff]), "+/8=");
        assert_eq!(base64url(&[0xfb, 0xff]), "-_8");
    }

    #[test]
    fn test_a_pem_body_is_wrapped_where_every_other_tool_expects_it() {
        let armoured = pem("PRIVATE KEY", &[0_u8; 96]);
        let body: Vec<&str> = armoured
            .lines()
            .filter(|line| !line.starts_with("-----"))
            .collect();

        assert!(armoured.starts_with("-----BEGIN PRIVATE KEY-----\n"));
        assert!(armoured.ends_with("-----END PRIVATE KEY-----\n"));
        assert_eq!(body.len(), 2);
        assert_eq!(body[0].len(), PEM_WIDTH);
    }

    #[test]
    fn test_what_was_written_reads_back_byte_for_byte() {
        for length in [0, 1, 2, 3, 31, 32, 48, 85] {
            let material: Vec<u8> = (0..length).map(|index| (index * 7 % 251) as u8).collect();

            assert_eq!(
                from_pem(&pem("PRIVATE KEY", &material)),
                Some(material.clone()),
                "round-tripping {length} bytes"
            );
        }
    }

    #[test]
    fn test_the_url_alphabet_round_trips_too() {
        // What a JWK carries, and therefore what a signature verifier has to be able to read back.
        for length in [0, 1, 2, 32, 64] {
            let material: Vec<u8> = (0..length).map(|index| (index * 11 % 253) as u8).collect();

            assert_eq!(
                from_base64url(&base64url(&material)),
                Some(material.clone()),
                "round-tripping {length} bytes"
            );
        }
    }

    #[test]
    fn test_something_that_is_not_base64_is_refused_rather_than_guessed_at() {
        assert_eq!(from_pem("-----BEGIN X-----\n!!!!\n-----END X-----\n"), None);
    }
}
