# Copyright (c) 2022 Nitro Agility S.r.l.
# SPDX-License-Identifier: Apache-2.0

"""Independent generator for contracts/vectors/plan.json (WP-3.9).

Computes a key revocation's plan body and digest, the plan receipt naming it and a second
operator's approval, both COSE_Sign1 under a Host's `host.operations` key, from the owner
decisions of 2026-10-11 (the label tables in status.md and contracts/cbor/operation-plan.json)
with Python's standard library and `cryptography`, never by calling the Rust codecs, so the Rust
tests compare two implementations. The `host.operations` key is the RFC 8032 section 7.1 test 2
key. Ed25519 is deterministic, so every byte is fixed.
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
PLAN_ID = bytes.fromhex("01a3185c5000711a8222222222222222")
NONCE = bytes([0x4E]) * 16
AT = 1_800_000_000
BODY_DOMAIN = b"permguard.operation.plan-body.v1\n"
RECEIPT_TYPE = "permguard.operation.plan.v1"
APPROVAL_TYPE = "permguard.operation.approval.v1"
OPERATION = "keys.revoke"
TARGET = "data.attest:" + "A" * 43
REVISION = 3
PARAMETERS = {"reason": "the key left the building", "compromised_at": "1799990000"}

# What the plan changes, and its digest.
body = cbor({1: OPERATION, 2: TARGET, 3: REVISION, 4: PARAMETERS})
plan_digest = "sha256:" + hashlib.sha256(BODY_DOMAIN + body).hexdigest()

# The receipt: a key revocation under dual control, so it needs one approval and lives a day.
receipt_payload = cbor({1: PLAN_ID, 2: OPERATION, 3: TARGET, 4: REVISION,
                        5: "spiffe://acme/operators/alice", 6: plan_digest, 7: AT + 86_400,
                        8: NONCE, 9: 1, 10: HOST_ID, 11: AT})
receipt = sign1(OPERATIONS, RECEIPT_TYPE, KID.encode(), receipt_payload)

# Another operator's approval, attested by the same Host.
approval_payload = cbor({1: plan_digest, 2: "spiffe://acme/operators/bob", 3: AT + 600,
                         4: HOST_ID})
approval = sign1(OPERATIONS, APPROVAL_TYPE, KID.encode(), approval_payload)

out = {"comment": "Plan body, receipt and approval (WP-3.9); see README.md and plan.py",
       "operations": {"seed": SEED_OPERATIONS, "public_key": OPERATIONS_PUB.hex(), "kid": KID,
                      "jwk": JWK},
       "host_id": HOST_ID.hex(), "plan_id": PLAN_ID.hex(), "nonce": NONCE.hex(),
       "plan_body": {"bytes": body.hex(), "digest": plan_digest},
       "receipt": {"payload": receipt_payload.hex(), "cose_sign1": receipt.hex()},
       "approval": {"payload": approval_payload.hex(), "cose_sign1": approval.hex()}}

json.dump(out, sys.stdout, indent=2, ensure_ascii=False)
sys.stdout.write("\n")
