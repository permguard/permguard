# Copyright (c) 2022 Nitro Agility S.r.l.
# SPDX-License-Identifier: Apache-2.0

"""Independent generator for contracts/vectors/identity.json (WP-2.2).

Computes the Host identity's records from the owner decisions of 2026-10-08 with Python's standard
library and `cryptography`, never by calling the Rust codecs, so the Rust tests compare two
implementations. Epoch 1 signs with the RFC 8032 section 7.1 test 1 key, epoch 2 is the test 2
key: Ed25519 is deterministic, so every byte is fixed.
"""
import hashlib, json, struct, sys
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

def key(seed_hex):
    k = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(seed_hex))
    return k, k.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)

SEED_1 = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
SEED_2 = "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb"
KEY_1, PUB_1 = key(SEED_1)
KEY_2, PUB_2 = key(SEED_2)
assert PUB_1.hex() == "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
assert PUB_2.hex() == "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c"

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

def fingerprint(pub): return "sha256:" + hashlib.sha256(pub).hexdigest()

def sign1(key, content_type, kid, payload):
    # COSE_Sign1, protected {1 alg EdDSA, 3 content type, 4 kid}, empty unprotected, no AAD.
    protected = cbor({1: -8, 3: content_type, 4: kid})
    signature = key.sign(cbor(["Signature1", protected, b"", payload]))
    return cbor([protected, {}, payload, signature])

# A UUIDv7 (RFC 9562): 48 bits of Unix milliseconds, version 7, the variant, ten bytes of 0x11.
MILLIS = 1_800_000_000_000
host_id = bytearray(MILLIS.to_bytes(8, "big")[2:] + bytes([0x11]) * 10)
host_id[6] = (host_id[6] & 0x0F) | 0x70
host_id[8] = (host_id[8] & 0x3F) | 0x80
host_id = bytes(host_id)
h = host_id.hex()
uuid = f"{h[0:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:32]}"
subject = f"urn:permguard:host:v1:{uuid}"
VOLUME_ID = bytes([0x22]) * 16
PROTOCOLS = ["permguard.host.session.v1"]
ZERO = "sha256:" + "0" * 64

out = {"comment": "Host identity records (WP-2.2); see README.md and identity.py",
       "host_id": h, "uuid": uuid, "subject": subject, "volume_id": VOLUME_ID.hex(),
       "epoch_1": {"seed": SEED_1, "public_key": PUB_1.hex(), "fingerprint": fingerprint(PUB_1)},
       "epoch_2": {"seed": SEED_2, "public_key": PUB_2.hex(), "fingerprint": fingerprint(PUB_2)}}

document_1 = cbor({1: host_id, 2: subject, 3: 1, 4: "pg-ed25519-sha256-v1", 5: PUB_1,
                   6: fingerprint(PUB_1), 8: PROTOCOLS, 9: 1, 10: 1_800_000_000})
out["document_epoch_1"] = {"payload": document_1.hex(),
                           "cose_sign1": sign1(KEY_1, "permguard.host.identity.v1", b"1", document_1).hex()}

succession = cbor({1: host_id, 2: 1, 3: 2, 4: fingerprint(PUB_2), 5: PUB_2, 6: ZERO, 7: 1_800_000_100})
succession_envelope = sign1(KEY_1, "permguard.host.succession.v1", b"1", succession)
succession_digest = "sha256:" + hashlib.sha256(b"permguard.host.succession.v1\n" + succession_envelope).hexdigest()
out["succession_1_to_2"] = {"payload": succession.hex(), "cose_sign1": succession_envelope.hex(),
                            "digest": succession_digest}

document_2 = cbor({1: host_id, 2: subject, 3: 2, 4: "pg-ed25519-sha256-v1", 5: PUB_2,
                   6: fingerprint(PUB_2), 7: succession_digest, 8: PROTOCOLS, 9: 2, 10: 1_800_000_100})
out["document_epoch_2"] = {"payload": document_2.hex(),
                           "cose_sign1": sign1(KEY_2, "permguard.host.identity.v1", b"2", document_2).hex()}

init = cbor({1: host_id, 2: VOLUME_ID, 3: fingerprint(PUB_1), 4: 1_800_000_000})
out["init"] = {"bytes": init.hex()}
out["witness"] = "sha256:" + hashlib.sha256(
    b"permguard.host.identity.witness.v1\n" + init + VOLUME_ID + fingerprint(PUB_1).encode()).hexdigest()
out["boot"] = {"boot_id": "33" * 16, "generation": 4,
               "bytes": cbor({1: bytes([0x33]) * 16, 2: 4}).hex()}

json.dump(out, sys.stdout, indent=2, ensure_ascii=False)
sys.stdout.write("\n")
