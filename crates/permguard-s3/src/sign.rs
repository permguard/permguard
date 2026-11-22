// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The signature of a request, AWS Signature Version 4: what the object store checks before it
//! does anything, over the method, the path, the query, the headers named and the hash of the
//! body. The secret never leaves this module in any form but the signature.

use hmac::{Hmac, KeyInit as _, Mac as _};
use sha2::{Digest as _, Sha256};

/// Lowercase hexadecimal.
pub(crate) fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// The SHA-256 of `bytes`, in hexadecimal: how a request names its body.
pub(crate) fn sha256_hex(bytes: &[u8]) -> String {
    hex(&Sha256::digest(bytes))
}

fn mac(key: &[u8], message: &[u8]) -> Vec<u8> {
    // HMAC takes a key of any length.
    #[allow(clippy::expect_used)]
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC takes a key of any length");
    mac.update(message);
    mac.finalize().into_bytes().to_vec()
}

/// Percent-encodes `text` as the signature wants it: every byte but the unreserved ones, and
/// `/` kept when `path` says the text is a path.
pub(crate) fn encode(text: &str, path: bool) -> String {
    let mut out = String::with_capacity(text.len());
    for byte in text.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(char::from(byte));
            }
            b'/' if path => out.push('/'),
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

/// The query of a request as it is sent and signed: the pairs sorted by name, each encoded.
pub(crate) fn query(pairs: &[(&str, &str)]) -> String {
    let mut pairs: Vec<(String, String)> = pairs
        .iter()
        .map(|(name, value)| (encode(name, false), encode(value, false)))
        .collect();
    pairs.sort();
    pairs
        .iter()
        .map(|(name, value)| format!("{name}={value}"))
        .collect::<Vec<_>>()
        .join("&")
}

/// What a request is signed with.
pub(crate) struct Signer<'a> {
    pub access_key: &'a str,
    pub secret: &'a str,
    pub region: &'a str,
}

impl Signer<'_> {
    /// The `Authorization` header of a request: `path` and `query` as they are sent, `headers`
    /// every header signed, by lowercase name, `x-amz-date` among them as `at`
    /// (`YYYYMMDDTHHMMSSZ`), and `payload` the hash of the body.
    pub(crate) fn authorization(
        &self,
        method: &str,
        path: &str,
        query: &str,
        headers: &[(&str, &str)],
        payload: &str,
        at: &str,
    ) -> String {
        let mut headers: Vec<(&str, &str)> = headers.to_vec();
        headers.sort();
        let canonical: String = headers
            .iter()
            .map(|(name, value)| format!("{name}:{}\n", value.trim()))
            .collect();
        let signed = headers
            .iter()
            .map(|(name, _)| *name)
            .collect::<Vec<_>>()
            .join(";");
        let request = format!("{method}\n{path}\n{query}\n{canonical}\n{signed}\n{payload}");
        let day = at.get(..8).unwrap_or(at);
        let scope = format!("{day}/{}/s3/aws4_request", self.region);
        let to_sign = format!(
            "AWS4-HMAC-SHA256\n{at}\n{scope}\n{}",
            sha256_hex(request.as_bytes())
        );
        let mut key = mac(format!("AWS4{}", self.secret).as_bytes(), day.as_bytes());
        for part in [self.region, "s3", "aws4_request"] {
            key = mac(&key, part.as_bytes());
        }
        let signature = hex(&mac(&key, to_sign.as_bytes()));
        format!(
            "AWS4-HMAC-SHA256 Credential={}/{scope}, SignedHeaders={signed}, Signature={signature}",
            self.access_key
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The example of the object store's own documentation, a `GET` of a range of an object:
    /// the signature it publishes is the one made here.
    #[test]
    fn the_documented_example_is_signed_as_documented() {
        let signer = Signer {
            access_key: "AKIAIOSFODNN7EXAMPLE",
            secret: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            region: "us-east-1",
        };
        let empty = sha256_hex(b"");
        assert_eq!(
            empty,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        let authorization = signer.authorization(
            "GET",
            "/test.txt",
            "",
            &[
                ("host", "examplebucket.s3.amazonaws.com"),
                ("range", "bytes=0-9"),
                ("x-amz-content-sha256", &empty),
                ("x-amz-date", "20130524T000000Z"),
            ],
            &empty,
            "20130524T000000Z",
        );
        assert_eq!(
            authorization,
            "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request, \
             SignedHeaders=host;range;x-amz-content-sha256;x-amz-date, \
             Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41"
        );
    }

    #[test]
    fn a_query_is_sorted_and_encoded() {
        assert_eq!(
            query(&[
                ("prefix", "a/b c"),
                ("list-type", "2"),
                ("continuation-token", "x+y=")
            ]),
            "continuation-token=x%2By%3D&list-type=2&prefix=a%2Fb%20c"
        );
        assert_eq!(encode("a/b~c d", true), "a/b~c%20d");
    }
}
