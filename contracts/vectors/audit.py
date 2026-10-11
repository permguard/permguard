# Copyright (c) 2022 Nitro Agility S.r.l.
# SPDX-License-Identifier: Apache-2.0

"""Independent generator for contracts/vectors/audit.json (WP-3.7).

Computes an audit record and its digest, the checkpoint sealing it and the next one chained to it,
both signed under a Host's `host.operations` key, and the anchor naming the first, from the owner
decisions of 2026-10-07 and 2026-10-11 (the label tables in status.md and
contracts/cbor/audit.json) with Python's standard library and `cryptography`, never by calling the
Rust codecs, so the Rust tests compare two implementations. The `host.operations` key is the
RFC 8032 section 7.1 test 2 key. Ed25519 is deterministic, so every byte is fixed.
"""
import base64, hashlib, json, struct, sys
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

SEED_OPERATIONS = "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb"
OPERATIONS = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(SEED_OPERATIONS))
OPERATIONS_PUB = OPERATIONS.public_key().public_bytes(serialization.Encoding.Raw,
                                                      serialization.PublicFormat.Raw)

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

def digest(domain, data): return "sha256:" + hashlib.sha256(domain + data).hexdigest()

def sign1(signer, content_type, kid, payload):
    # COSE_Sign1, protected {1 alg EdDSA, 3 content type, 4 kid}, empty unprotected, no AAD.
    protected = cbor({1: -8, 3: content_type, 4: kid})
    signature = signer.sign(cbor(["Signature1", protected, b"", payload]))
    return cbor([protected, {}, payload, signature])

thumbprint = b64url(hashlib.sha256(
    ('{"crv":"Ed25519","kty":"OKP","x":"%s"}' % b64url(OPERATIONS_PUB)).encode()).digest())
KID = "host.operations:" + thumbprint
JWK = {"kid": KID, "kty": "OKP", "crv": "Ed25519", "x": b64url(OPERATIONS_PUB), "alg": "EdDSA",
       "use": "sig"}

HOST_ID = bytes.fromhex("01a3185c500071119111111111111111")
BOOT_ID = bytes([0xB0]) * 16
AT = 1_800_000_000
DAY = "2027-01-15"
ZEROS = "sha256:" + "0" * 64
TRAIL = "security:plane/control"
RECORD_DOMAIN = b"permguard.audit.record.v1\n"
CHECKPOINT_DOMAIN = b"permguard.audit.checkpoint.v1\n"
CONTENT_TYPE = "permguard.audit.checkpoint.v1"
CONFIG_REVISION = "sha256:" + hashlib.sha256(b"settings").hexdigest()

# The trail's first record: no operation, phase or target, one fact.
record = cbor({1: TRAIL, 2: 0, 5: HOST_ID, 6: BOOT_ID, 7: "control-plane", 8: "zone.created",
               9: "catalog", 10: "plane/control", 12: "ok", 13: {"count": 1}, 14: "9.9.9",
               15: CONFIG_REVISION, 16: AT, 17: 1500, 18: ZEROS})
record_digest = digest(RECORD_DOMAIN, record)

# The seal of its day, the first checkpoint of the trail.
first_payload = cbor({1: TRAIL, 2: DAY, 3: 0, 4: 0, 5: record_digest, 6: ZEROS, 7: HOST_ID,
                      8: 1, 9: AT + 86_400})
first = sign1(OPERATIONS, CONTENT_TYPE, KID.encode(), first_payload)
first_digest = digest(CHECKPOINT_DOMAIN, first)

# An on-demand checkpoint of the next day, chained to the seal; its head stands for a record of
# that day.
second_head = "sha256:" + hashlib.sha256(b"the record 7").hexdigest()
second_payload = cbor({1: TRAIL, 2: "2027-01-16", 3: 1, 4: 7, 5: second_head, 6: first_digest,
                       7: HOST_ID, 8: 2, 9: AT + 90_000})
second = sign1(OPERATIONS, CONTENT_TYPE, KID.encode(), second_payload)

# The anchor retention writes before deleting the first day.
anchor = cbor({1: TRAIL, 2: 1, 3: DAY, 4: first_digest})

out = {"comment": "Audit record, checkpoints and anchor (WP-3.7); see README.md and audit.py",
       "operations": {"seed": SEED_OPERATIONS, "public_key": OPERATIONS_PUB.hex(), "kid": KID,
                      "jwk": JWK},
       "host_id": HOST_ID.hex(), "boot_id": BOOT_ID.hex(),
       "record": {"bytes": record.hex(), "digest": record_digest},
       "checkpoint_first": {"payload": first_payload.hex(), "cose_sign1": first.hex(),
                            "digest": first_digest},
       "checkpoint_second": {"payload": second_payload.hex(), "cose_sign1": second.hex(),
                             "digest": digest(CHECKPOINT_DOMAIN, second), "head": second_head},
       "anchor": anchor.hex()}

json.dump(out, sys.stdout, indent=2, ensure_ascii=False)
sys.stdout.write("\n")
