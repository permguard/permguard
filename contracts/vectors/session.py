# Copyright (c) 2022 Nitro Agility S.r.l.
# SPDX-License-Identifier: Apache-2.0

"""Independent generator for contracts/vectors/session.json (WP-2.3).

Computes a peer Host session's messages and proofs from the owner decisions of 2026-10-08 with
Python's standard library and `cryptography`, never by calling the Rust codecs, so the Rust tests
compare two implementations. Host A signs with the RFC 8032 section 7.1 test 1 key, B with test 2
and C with test 3: Ed25519 is deterministic, so every byte is fixed. The negative cases are proofs
a verifier must refuse against the transcript it expects: a replay, a relay, a reflection and an
unknown-key share.
"""
import hashlib, json, struct, sys
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

def key(seed_hex):
    k = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(seed_hex))
    return k, k.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)

SEED_A = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
SEED_B = "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb"
SEED_C = "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7"
KEY_A, PUB_A = key(SEED_A)
KEY_B, PUB_B = key(SEED_B)
KEY_C, PUB_C = key(SEED_C)
assert PUB_C.hex() == "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025"

def head(major, n):
    if n < 24: return bytes([major << 5 | n])
    if n < 256: return bytes([major << 5 | 24, n])
    if n < 65536: return bytes([major << 5 | 25]) + struct.pack(">H", n)
    if n < 2 ** 32: return bytes([major << 5 | 26]) + struct.pack(">I", n)
    return bytes([major << 5 | 27]) + struct.pack(">Q", n)

def cbor(v):
    # RFC 8949 core deterministic encoding, for the types these messages use.
    if isinstance(v, bool): return b"\xf5" if v else b"\xf4"
    if isinstance(v, int): return head(0, v) if v >= 0 else head(1, -1 - v)
    if isinstance(v, bytes): return head(2, len(v)) + v
    if isinstance(v, str): b = v.encode(); return head(3, len(b)) + b
    if isinstance(v, list): return head(4, len(v)) + b"".join(cbor(x) for x in v)
    if isinstance(v, dict):
        items = sorted(((cbor(k), cbor(x)) for k, x in v.items()), key=lambda kv: kv[0])
        return head(5, len(items)) + b"".join(k + x for k, x in items)
    raise TypeError(v)

def sign1(key, content_type, kid, payload):
    # COSE_Sign1, protected {1 alg EdDSA, 3 content type, 4 kid}, empty unprotected, no AAD.
    protected = cbor({1: -8, 3: content_type, 4: kid})
    signature = key.sign(cbor(["Signature1", protected, b"", payload]))
    return cbor([protected, {}, payload, signature])

def digest(domain, data): return "sha256:" + hashlib.sha256(domain + data).hexdigest()

def host_id(byte):
    # A UUIDv7 (RFC 9562): 48 bits of Unix milliseconds, version 7, the variant, ten equal bytes.
    h = bytearray((1_800_000_000_000).to_bytes(8, "big")[2:] + bytes([byte]) * 10)
    h[6] = (h[6] & 0x0F) | 0x70
    h[8] = (h[8] & 0x3F) | 0x80
    return bytes(h)

A, B, C = host_id(0x11), host_id(0x22), host_id(0x33)
PROOF = "permguard.host.proof.v1"
NONCE_A, NONCE_B, NONCE_B2 = bytes([0xA1]) * 16, bytes([0xB1]) * 16, bytes([0xB2]) * 16
EXPORTER, OTHER_EXPORTER = bytes([0xE1]) * 32, bytes([0xE2]) * 32
EXPIRES = 1_800_000_060

hello = cbor({1: 1, 2: A, 3: 1, 4: "production", 5: NONCE_A, 6: "enroll"})
hello_digest = digest(b"permguard.host.session.hello.v1\n", hello)

def challenge(host, nonce):
    return cbor({1: host, 2: 1, 3: "production", 4: nonce, 5: EXPIRES})

def transcript(responder, nonce_b, exporter, challenge_bytes, signer):
    return cbor({1: "permguard.host.session.v1", 2: A, 3: responder, 4: 1, 5: 1, 6: NONCE_A,
                 7: nonce_b, 10: "enroll", 11: EXPIRES, 12: exporter, 13: hello_digest,
                 14: digest(b"permguard.host.session.challenge.v1\n", challenge_bytes),
                 15: signer})

challenge_b = challenge(B, NONCE_B)
initiator = transcript(B, NONCE_B, EXPORTER, challenge_b, "initiator")
responder = transcript(B, NONCE_B, EXPORTER, challenge_b, "responder")
proof_a = sign1(KEY_A, PROOF, b"1", initiator)
proof_b = sign1(KEY_B, PROOF, b"1", responder)

# Replay: A's proof of this session against a later one's challenge, which carries another nonce.
challenge_later = challenge(B, NONCE_B2)
replay = transcript(B, NONCE_B2, EXPORTER, challenge_later, "initiator")
# Relay: B's connection to the relay exports another value than A's connection to it.
relay = transcript(B, NONCE_B, OTHER_EXPORTER, challenge_b, "initiator")
# Reflection: B signs the initiator's transcript, its own key over the right session in the
# other role; the initiator expects the responder's.
# Unknown-key share: A believes it speaks to C, the challenge rewritten to name C.
challenge_c = challenge(C, NONCE_B)
proof_to_c = sign1(KEY_A, PROOF, b"1", transcript(C, NONCE_B, EXPORTER, challenge_c, "initiator"))

def host(id_, seed, pub):
    return {"host_id": id_.hex(), "seed": seed, "public_key": pub.hex(),
            "fingerprint": "sha256:" + hashlib.sha256(pub).hexdigest()}

out = {"comment": "Peer Host session messages and proofs (WP-2.3); see README.md and session.py",
       "a": host(A, SEED_A, PUB_A), "b": host(B, SEED_B, PUB_B), "c": host(C, SEED_C, PUB_C),
       "nonce_a": NONCE_A.hex(), "nonce_b": NONCE_B.hex(), "expires": EXPIRES,
       "exporter": EXPORTER.hex(),
       "hello": {"bytes": hello.hex(), "digest": hello_digest},
       "challenge": {"bytes": challenge_b.hex(),
                     "digest": digest(b"permguard.host.session.challenge.v1\n", challenge_b)},
       "transcript_initiator": initiator.hex(), "transcript_responder": responder.hex(),
       "proof_initiator": proof_a.hex(), "proof_responder": proof_b.hex(),
       "refused": [
           {"case": "replay", "proof": proof_a.hex(), "signer": "a", "expected": replay.hex(),
            "later_challenge": challenge_later.hex()},
           {"case": "relay", "proof": proof_a.hex(), "signer": "a", "expected": relay.hex(),
            "other_exporter": OTHER_EXPORTER.hex()},
           {"case": "reflection", "proof": sign1(KEY_B, PROOF, b"1", initiator).hex(), "signer": "b",
            "expected": responder.hex()},
           {"case": "unknown_key_share", "proof": proof_to_c.hex(), "signer": "a",
            "expected": initiator.hex(), "challenge_to_c": challenge_c.hex()},
       ]}

json.dump(out, sys.stdout, indent=2, ensure_ascii=False)
sys.stdout.write("\n")
