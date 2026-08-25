// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The canonical CBOR profile — RFC 8949 Core Deterministic Encoding,
//! restricted to what the specification allows: definite lengths only,
//! shortest integer encoding, bytewise-sorted map keys, no duplicates, no
//! tags, no floats, no simple values.
//!
//! The codec is deliberately in-house: the profile is a few dozen lines of
//! rules, and owning them means an unsupported byte is rejected here, by
//! construction, rather than by remembering to configure a general-purpose
//! library strictly enough.
//!
//! Canonical ingest is one call: [`decode_canonical`] decodes strictly and
//! then re-encodes, accepting the input only if it is byte-identical to its
//! own canonical form.

use std::fmt;

/// The value model of the profile. Nothing outside it decodes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    /// Majors 0 and 1, folded into one signed integer.
    Int(i64),
    /// Major 7, simple values 20/21 only — the two booleans a schema may
    /// list; every other simple value stays outside the profile.
    Bool(bool),
    /// Major 2.
    Bytes(Vec<u8>),
    /// Major 3, valid UTF-8.
    Text(String),
    /// Major 4.
    Array(Vec<Value>),
    /// Major 5. Pairs are stored in encoding order; the encoder sorts them
    /// bytewise by encoded key and the strict decoder rejects unsorted or
    /// duplicate keys, so a decoded map is always canonical.
    Map(Vec<(Value, Value)>),
}

/// Why an encoding was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CborError {
    /// The input ended before the value did.
    Truncated,
    /// A construct outside the profile: tag, float, simple value,
    /// indefinite length, or an unknown additional-information encoding.
    Unsupported(&'static str),
    /// An integer was not in its shortest form.
    NotShortest,
    /// Map keys out of bytewise order, or repeated.
    KeyOrder,
    /// Text bytes that are not UTF-8.
    Utf8,
    /// The value decoded, but the input bytes are not its canonical form.
    NotCanonical,
    /// Bytes remained after the single expected value.
    TrailingBytes,
    /// An integer does not fit the model (beyond i64).
    IntRange,
}

impl fmt::Display for CborError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CborError::Truncated => write!(f, "truncated input"),
            CborError::Unsupported(what) => write!(f, "unsupported construct: {what}"),
            CborError::NotShortest => write!(f, "integer not in shortest encoding"),
            CborError::KeyOrder => write!(f, "map keys unsorted or duplicated"),
            CborError::Utf8 => write!(f, "text is not valid utf-8"),
            CborError::NotCanonical => write!(f, "input is not the canonical encoding"),
            CborError::TrailingBytes => write!(f, "trailing bytes after value"),
            CborError::IntRange => write!(f, "integer out of the supported range"),
        }
    }
}

impl std::error::Error for CborError {}

/// Encode a value in the canonical form of the profile.
pub fn encode(value: &Value) -> Vec<u8> {
    let mut out = Vec::new();
    encode_into(value, &mut out);
    out
}

fn encode_into(value: &Value, out: &mut Vec<u8>) {
    match value {
        Value::Bool(b) => out.push(if *b { 0xf5 } else { 0xf4 }),
        Value::Int(n) => {
            if *n >= 0 {
                encode_head(0, *n as u64, out);
            } else {
                encode_head(1, (-1 - *n) as u64, out);
            }
        }
        Value::Bytes(b) => {
            encode_head(2, b.len() as u64, out);
            out.extend_from_slice(b);
        }
        Value::Text(s) => {
            encode_head(3, s.len() as u64, out);
            out.extend_from_slice(s.as_bytes());
        }
        Value::Array(items) => {
            encode_head(4, items.len() as u64, out);
            for item in items {
                encode_into(item, out);
            }
        }
        Value::Map(pairs) => {
            let mut encoded: Vec<(Vec<u8>, Vec<u8>)> =
                pairs.iter().map(|(k, v)| (encode(k), encode(v))).collect();
            encoded.sort_by(|a, b| a.0.cmp(&b.0));
            encode_head(5, encoded.len() as u64, out);
            for (k, v) in encoded {
                out.extend_from_slice(&k);
                out.extend_from_slice(&v);
            }
        }
    }
}

fn encode_head(major: u8, arg: u64, out: &mut Vec<u8>) {
    let m = major << 5;
    if arg < 24 {
        out.push(m | arg as u8);
    } else if arg <= u8::MAX as u64 {
        out.push(m | 24);
        out.push(arg as u8);
    } else if arg <= u16::MAX as u64 {
        out.push(m | 25);
        out.extend_from_slice(&(arg as u16).to_be_bytes());
    } else if arg <= u32::MAX as u64 {
        out.push(m | 26);
        out.extend_from_slice(&(arg as u32).to_be_bytes());
    } else {
        out.push(m | 27);
        out.extend_from_slice(&arg.to_be_bytes());
    }
}

/// Decode exactly one value, then require the input to be byte-identical to
/// the canonical re-encoding — the ingest rule of the specification.
pub fn decode_canonical(input: &[u8]) -> Result<Value, CborError> {
    let mut cursor = Cursor { input, pos: 0 };
    let value = cursor.decode_value()?;
    if cursor.pos != input.len() {
        return Err(CborError::TrailingBytes);
    }
    if encode(&value) != input {
        return Err(CborError::NotCanonical);
    }
    Ok(value)
}

struct Cursor<'a> {
    input: &'a [u8],
    pos: usize,
}

impl Cursor<'_> {
    fn take(&mut self, n: usize) -> Result<&[u8], CborError> {
        let end = self.pos.checked_add(n).ok_or(CborError::Truncated)?;
        if end > self.input.len() {
            return Err(CborError::Truncated);
        }
        let slice = &self.input[self.pos..end];
        self.pos = end;
        Ok(slice)
    }

    fn decode_head(&mut self) -> Result<(u8, u64), CborError> {
        let first = self.take(1)?[0];
        let major = first >> 5;
        let info = first & 0x1f;
        // Outside the profile entirely: reject before interpreting the
        // argument, so a float never reads as a "non-shortest integer".
        if major == 6 {
            return Err(CborError::Unsupported("tag"));
        }
        if major == 7 {
            // The booleans are the one exception the profile lists.
            if first == 0xf4 || first == 0xf5 {
                return Ok((7, u64::from(first & 0x01)));
            }
            return Err(CborError::Unsupported("float or simple value"));
        }
        let arg = match info {
            0..=23 => info as u64,
            24 => {
                let v = self.take(1)?[0] as u64;
                if v < 24 {
                    return Err(CborError::NotShortest);
                }
                v
            }
            25 => {
                let v = u16::from_be_bytes(self.take(2)?.try_into().unwrap()) as u64;
                if v <= u8::MAX as u64 {
                    return Err(CborError::NotShortest);
                }
                v
            }
            26 => {
                let v = u32::from_be_bytes(self.take(4)?.try_into().unwrap()) as u64;
                if v <= u16::MAX as u64 {
                    return Err(CborError::NotShortest);
                }
                v
            }
            27 => {
                let v = u64::from_be_bytes(self.take(8)?.try_into().unwrap());
                if v <= u32::MAX as u64 {
                    return Err(CborError::NotShortest);
                }
                v
            }
            31 => return Err(CborError::Unsupported("indefinite length")),
            _ => return Err(CborError::Unsupported("reserved additional information")),
        };
        Ok((major, arg))
    }

    fn decode_value(&mut self) -> Result<Value, CborError> {
        let (major, arg) = self.decode_head()?;
        match major {
            0 => i64::try_from(arg)
                .map(Value::Int)
                .map_err(|_| CborError::IntRange),
            1 => {
                let n = i64::try_from(arg).map_err(|_| CborError::IntRange)?;
                n.checked_neg()
                    .and_then(|v| v.checked_sub(1))
                    .map(Value::Int)
                    .ok_or(CborError::IntRange)
            }
            2 => Ok(Value::Bytes(self.take(arg as usize)?.to_vec())),
            3 => {
                let bytes = self.take(arg as usize)?.to_vec();
                String::from_utf8(bytes)
                    .map(Value::Text)
                    .map_err(|_| CborError::Utf8)
            }
            4 => {
                let mut items = Vec::new();
                for _ in 0..arg {
                    items.push(self.decode_value()?);
                }
                Ok(Value::Array(items))
            }
            5 => {
                let mut pairs = Vec::new();
                let mut previous_key: Option<Vec<u8>> = None;
                for _ in 0..arg {
                    let key = self.decode_value()?;
                    let encoded_key = encode(&key);
                    if let Some(prev) = &previous_key
                        && *prev >= encoded_key
                    {
                        return Err(CborError::KeyOrder);
                    }
                    previous_key = Some(encoded_key);
                    let value = self.decode_value()?;
                    pairs.push((key, value));
                }
                Ok(Value::Map(pairs))
            }
            6 => Err(CborError::Unsupported("tag")),
            7 => Ok(Value::Bool(arg == 1)),
            _ => Err(CborError::Unsupported("float or simple value")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn integers_round_trip_in_shortest_form() {
        for n in [
            0i64,
            1,
            23,
            24,
            255,
            256,
            65535,
            65536,
            -1,
            -24,
            -25,
            -256,
            i64::MAX,
            i64::MIN,
        ] {
            let bytes = encode(&Value::Int(n));
            assert_eq!(decode_canonical(&bytes).unwrap(), Value::Int(n));
        }
    }

    #[test]
    fn long_form_integer_is_rejected() {
        // 0x18 0x00 is `0` encoded with one needless byte.
        assert_eq!(decode_canonical(&[0x18, 0x00]), Err(CborError::NotShortest));
    }

    #[test]
    fn maps_encode_sorted_and_reject_unsorted_input() {
        let map = Value::Map(vec![
            (Value::Int(2), Value::Text("b".into())),
            (Value::Int(1), Value::Text("a".into())),
        ]);
        let bytes = encode(&map);
        let decoded = decode_canonical(&bytes).unwrap();
        // Decoded pairs come back in canonical (sorted) order.
        assert_eq!(
            decoded,
            Value::Map(vec![
                (Value::Int(1), Value::Text("a".into())),
                (Value::Int(2), Value::Text("b".into())),
            ])
        );
        // A hand-built unsorted map: {2: 0, 1: 0}.
        assert_eq!(
            decode_canonical(&[0xa2, 0x02, 0x00, 0x01, 0x00]),
            Err(CborError::KeyOrder)
        );
        // A duplicate key: {1: 0, 1: 0}.
        assert_eq!(
            decode_canonical(&[0xa2, 0x01, 0x00, 0x01, 0x00]),
            Err(CborError::KeyOrder)
        );
    }

    #[test]
    fn profile_rejects_tags_floats_and_indefinite_lengths() {
        // Tag 0 around an integer.
        assert!(matches!(
            decode_canonical(&[0xc0, 0x00]),
            Err(CborError::Unsupported(_))
        ));
        // Float 0.0 (major 7).
        assert!(matches!(
            decode_canonical(&[0xf9, 0x00, 0x00]),
            Err(CborError::Unsupported(_))
        ));
        // Indefinite-length array.
        assert!(matches!(
            decode_canonical(&[0x9f, 0xff]),
            Err(CborError::Unsupported(_))
        ));
    }

    #[test]
    fn trailing_bytes_are_rejected() {
        assert_eq!(
            decode_canonical(&[0x00, 0x00]),
            Err(CborError::TrailingBytes)
        );
    }

    #[test]
    fn known_encodings_match_rfc_8949() {
        assert_eq!(encode(&Value::Int(10)), vec![0x0a]);
        assert_eq!(encode(&Value::Int(-10)), vec![0x29]);
        assert_eq!(encode(&Value::Int(1000)), vec![0x19, 0x03, 0xe8]);
        assert_eq!(
            encode(&Value::Text("IETF".into())),
            vec![0x64, 0x49, 0x45, 0x54, 0x46]
        );
        assert_eq!(
            encode(&Value::Bytes(vec![1, 2, 3, 4])),
            vec![0x44, 1, 2, 3, 4]
        );
    }
}
