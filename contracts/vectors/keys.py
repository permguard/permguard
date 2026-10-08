# Copyright (c) 2022 Nitro Agility S.r.l.
# SPDX-License-Identifier: Apache-2.0

"""Independent generator for contracts/vectors/keys.json (WP-3.1).

Computes a key ring's records from the owner decisions of 2026-10-08 with Python's standard library
and `cryptography`, never by calling the Rust codecs, so the Rust tests compare two
implementations. The identity signs with the RFC 8032 section 7.1 test 1 key at epoch 1; the ring's
key is the test 2 key: Ed25519 is deterministic, so every byte is fixed.
"""
import base64, hashlib, json, struct, sys
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

def key(seed_hex):
    k = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(seed_hex))
    return k, k.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)

SEED_IDENTITY = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
SEED_RING = "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb"
IDENTITY, IDENTITY_PUB = key(SEED_IDENTITY)
_, RING_PUB = key(SEED_RING)

def head(major, n):
    if n < 24: return bytes([major << 5 | n])
    if n < 256: return bytes([major << 5 | 24, n])
    if n < 65536: return bytes([major << 5 | 25]) + struct.pack(">H", n)
    if n < 2 ** 32: return bytes([major << 5 | 26]) + struct.pack(">I", n)
    return bytes([major << 5 | 27]) + struct.pack(">Q", n)

def cbor(v):
    # RFC 8949 core deterministic encoding, for the types these records use.
    if isinstance(v, bool): return b"\xf5" if v else b"\xf4"
    if isinstance(v, int): return head(0, v) if v >= 0 else head(1, -1 - v)
    if isinstance(v, bytes): return head(2, len(v)) + v
    if isinstance(v, str): b = v.encode(); return head(3, len(b)) + b
    if isinstance(v, list): return head(4, len(v)) + b"".join(cbor(x) for x in v)
    if isinstance(v, dict):
        items = sorted(((cbor(k), cbor(x)) for k, x in v.items()), key=lambda kv: kv[0])
        return head(5, len(items)) + b"".join(k + x for k, x in items)
    raise TypeError(v)

def b64url(data): return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

def sign1(signer, content_type, kid, payload):
    # COSE_Sign1, protected {1 alg EdDSA, 3 content type, 4 kid}, empty unprotected, no AAD.
    protected = cbor({1: -8, 3: content_type, 4: kid})
    signature = signer.sign(cbor(["Signature1", protected, b"", payload]))
    return cbor([protected, {}, payload, signature])

# The Host of identity.py: a UUIDv7 of 1_800_000_000_000 ms and ten bytes of 0x11.
MILLIS = 1_800_000_000_000
host_id = bytearray(MILLIS.to_bytes(8, "big")[2:] + bytes([0x11]) * 10)
host_id[6] = (host_id[6] & 0x0F) | 0x70
host_id[8] = (host_id[8] & 0x3F) | 0x80
host_id = bytes(host_id)

RING = "data.attest"
SUITE = "pg-ed25519-sha256-v1"
AT = 1_800_000_000
# RFC 7638: the required members in lexicographic order, no whitespace.
thumbprint = b64url(hashlib.sha256(
    ('{"crv":"Ed25519","kty":"OKP","x":"%s"}' % b64url(RING_PUB)).encode()).digest())
kid = RING + ":" + thumbprint
# The JWK as the ring publishes it: kid, kty, crv, x, alg, use.
jwk = json.dumps({"kid": kid, "kty": "OKP", "crv": "Ed25519", "x": b64url(RING_PUB),
                  "alg": "EdDSA", "use": "sig"}, separators=(",", ":"))
key_set = cbor({"ring": RING, "epoch": 1, "algorithm": SUITE, "keys_by_thumbprint": [thumbprint]})
key_set_digest = hashlib.sha256(b"permguard.key-set.v1\n" + key_set).digest()

prepublished = cbor({1: 1, 2: "prepublished", 3: kid, 4: 1, 5: AT, 8: jwk})
activated = cbor({1: 2, 2: "activated", 3: kid, 4: 1, 5: AT})
view = cbor({1: RING, 2: SUITE, 3: 1, 4: key_set_digest,
             5: [{1: kid, 2: "active", 3: jwk, 4: AT, 5: AT}]})
binding = cbor({1: host_id, 2: RING, 3: 1, 4: key_set_digest, 5: SUITE, 6: AT,
                7: AT + 30 * 86400})

out = {"comment": "Key ring records (WP-3.1); see README.md and keys.py",
       "host_id": host_id.hex(),
       "identity": {"seed": SEED_IDENTITY, "public_key": IDENTITY_PUB.hex(), "epoch": 1},
       "ring_key": {"seed": SEED_RING, "public_key": RING_PUB.hex()},
       "ring": RING, "thumbprint": thumbprint, "kid": kid, "jwk": jwk,
       "key_set": {"bytes": key_set.hex(), "digest": key_set_digest.hex()},
       "journal": {"prepublished": prepublished.hex(), "activated": activated.hex()},
       "ring_view": view.hex(),
       "binding": {"payload": binding.hex(),
                   "cose_sign1": sign1(IDENTITY, "permguard.host.ring-binding.v1", b"1", binding).hex()}}

json.dump(out, sys.stdout, indent=2, ensure_ascii=False)
sys.stdout.write("\n")
