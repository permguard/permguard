# Copyright (c) 2022 Nitro Agility S.r.l.
# SPDX-License-Identifier: Apache-2.0

"""Independent generator for contracts/vectors/notp.json (WP-7.1).

Computes the NOTP target records from the owner decisions of 2026-10-14 (status.md) with Python's
standard library and `cryptography`, never by calling the Rust codecs: two ref states and their
`ref_digest`, the head statement binding the authority, the ref digest and the ring's epoch and key
set, signed under the RFC 8032 section 7.1 test 1 key, the messages that carry them, and a manifest
whose partition promises its interfaces, with the encodings a reader refuses.
Ed25519 is deterministic, so every byte is fixed.
"""
import hashlib, json, struct, sys
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

SEED = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
KEY = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(SEED))
PUBLIC = KEY.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
KID = "control.attest:vector"
REF_STATE = b"permguard.notp.ref-state.v1\n"
HEAD_TYPE = "application/vnd.permguard.head.v1+cbor"
NATIVE = "permguard.api.pdp.native.v1"
TEMPORAL = "permguard.api.pdp.temporal.v1alpha1"

def head(major, n):
    if n < 24: return bytes([major << 5 | n])
    if n < 256: return bytes([major << 5 | 24, n])
    if n < 65536: return bytes([major << 5 | 25]) + struct.pack(">H", n)
    if n < 2 ** 32: return bytes([major << 5 | 26]) + struct.pack(">I", n)
    return bytes([major << 5 | 27]) + struct.pack(">Q", n)

def cbor(v):
    # RFC 8949 core deterministic encoding, for the types these records use.
    if v is True: return b"\xf5"
    if v is False: return b"\xf4"
    if isinstance(v, int): return head(0, v) if v >= 0 else head(1, -1 - v)
    if isinstance(v, bytes): return head(2, len(v)) + v
    if isinstance(v, str): b = v.encode(); return head(3, len(b)) + b
    if isinstance(v, list): return head(4, len(v)) + b"".join(cbor(x) for x in v)
    if isinstance(v, dict):
        items = sorted(((cbor(k), cbor(x)) for k, x in v.items()), key=lambda kv: kv[0])
        return head(5, len(items)) + b"".join(k + x for k, x in items)
    raise TypeError(v)

def digest(data): return "sha256:" + hashlib.sha256(data).hexdigest()

# Ref states: a first one, and the one after it.
HEAD_1 = digest(b"commit one")
HEAD_2 = digest(b"commit two")
first = cbor({1: HEAD_1, 2: 1})
first_digest = "sha256:" + hashlib.sha256(REF_STATE + first).hexdigest()
second = cbor({1: HEAD_2, 2: 2, 3: first_digest})
second_digest = "sha256:" + hashlib.sha256(REF_STATE + second).hexdigest()

# The head statement of the second state.
AUTHORITY = bytes.fromhex("01a3185c50007444d444444444444444")
KEY_SET = digest(b"control.attest key set")
statement = {1: "zone-a", 2: "ledger-1", 3: "refs/heads/main", 4: HEAD_2, 5: 2, 6: 1791194400,
             7: AUTHORITY, 8: second_digest, 9: 3, 10: KEY_SET}
protected = cbor({1: -8, 3: HEAD_TYPE, 4: KID.encode()})
payload = cbor(statement)
sig_structure = cbor(["Signature1", protected, b"", payload])
signature = KEY.sign(sig_structure)
sign1 = cbor([protected, {}, payload, signature])

# The messages.
TRANSFER = bytes([0x7a] * 16)
negotiate_push = cbor({1: "refs/heads/main", 2: HEAD_2,
                       4: [{1: digest(b"object"), 2: 120}],
                       5: {1: 1, 2: first_digest}, 6: "push-1"})
negotiate_push_answer = cbor({1: [digest(b"object")], 2: 1048576, 3: 256, 4: "deflate",
                              5: TRANSFER, 6: 4096, 7: 1791195000})
commit_push = cbor({1: "refs/heads/main", 2: HEAD_2, 4: {1: 1, 2: first_digest},
                    5: TRANSFER, 6: "commit-1"})
commit_push_answer = cbor({1: HEAD_2, 2: 2, 3: sign1, 4: second_digest})
get_ref_answer = cbor({1: HEAD_2, 2: 2, 3: sign1, 4: second_digest})
negotiate_pull = cbor({1: "refs/heads/main", 3: [], 4: {1: 1, 2: first_digest}})
# Today's `expected_old`, label 3: retired, refused.
retired = cbor({1: "refs/heads/main", 2: HEAD_2, 3: HEAD_1, 4: [], 6: "push-1"})

# A manifest whose partition promises both interfaces, and the encodings a reader refuses.
def manifest(interfaces, extra=None):
    partition = {1: "cedar", 2: ["application/vnd.permguard.policy.cedar"], 3: False}
    if interfaces is not None:
        partition[7] = interfaces
    if extra:
        partition.update(extra)
    return cbor({
        1: {1: "policy", 2: "ledger-1", 3: "a ledger", 4: "nitro", 5: "Apache-2.0"},
        2: {"cedar": {1: {1: "cedar", 2: ">=4.0.0"}, 2: {1: "permguard", 2: ">=0.1.0"}}},
        3: {"policies": partition},
        4: {"native": {1: NATIVE, 2: ["policies"]}, "temporal": {1: TEMPORAL, 2: ["policies"]}},
    })

out = {"comment": "NOTP target records (WP-7.1); see README.md and notp.py",
       "public": PUBLIC.hex(), "kid": KID,
       "ref_state": {"first": first.hex(), "first_digest": first_digest,
                     "second": second.hex(), "second_digest": second_digest,
                     "head_1": HEAD_1, "head_2": HEAD_2},
       "head_statement": {"zone": "zone-a", "ledger": "ledger-1", "ref": "refs/heads/main",
                          "counter": 2, "signed_at": 1791194400,
                          "authority_host_id": AUTHORITY.hex(), "ring_epoch": 3,
                          "key_set_digest": KEY_SET, "protected": protected.hex(),
                          "payload": payload.hex(), "cose_sign1": sign1.hex()},
       "messages": {"transfer_id": TRANSFER.hex(),
                    "negotiate_push": negotiate_push.hex(),
                    "negotiate_push_answer": negotiate_push_answer.hex(),
                    "commit_push": commit_push.hex(),
                    "commit_push_answer": commit_push_answer.hex(),
                    "get_ref_answer": get_ref_answer.hex(),
                    "negotiate_pull": negotiate_pull.hex(),
                    "retired_expected_old": retired.hex()},
       "manifest": {"interfaces": manifest([NATIVE, TEMPORAL]).hex(),
                    "legacy": manifest(None).hex(),
                    "unsorted": manifest([TEMPORAL, NATIVE]).hex(),
                    "duplicate": manifest([NATIVE, NATIVE]).hex(),
                    "empty": manifest([]).hex(),
                    "not_promised": manifest([NATIVE]).hex(),
                    "unknown_key": manifest([NATIVE, TEMPORAL], {8: True}).hex()}}

json.dump(out, sys.stdout, indent=2, ensure_ascii=False)
sys.stdout.write("\n")
