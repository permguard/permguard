# Copyright (c) 2022 Nitro Agility S.r.l.
# SPDX-License-Identifier: Apache-2.0

"""Independent generator for contracts/vectors/stream.json (WP-5.1).

Computes the stream engine's records from the owner decisions of 2026-10-13 (the label tables in
status.md) with Python's standard library and `cryptography`, never by calling the Rust codecs, so
the Rust tests compare two implementations: a genesis run statement carrying a fence and a
successor after a fork naming its predecessor and the approved plan, both COSE_Sign1
`permguard.stream.run.v1` under a `host.operations` key (the RFC 8032 section 7.1 test 2 key),
their digests, a run end, a group of records, a record digest and two STATEs.
Ed25519 is deterministic, so every byte is fixed.
"""
import hashlib, json, struct, sys
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
    if isinstance(v, int): return head(0, v) if v >= 0 else head(1, -1 - v)
    if isinstance(v, bytes): return head(2, len(v)) + v
    if isinstance(v, str): b = v.encode(); return head(3, len(b)) + b
    if isinstance(v, list): return head(4, len(v)) + b"".join(cbor(x) for x in v)
    if isinstance(v, dict):
        items = sorted(((cbor(k), cbor(x)) for k, x in v.items()), key=lambda kv: kv[0])
        return head(5, len(items)) + b"".join(k + x for k, x in items)
    raise TypeError(v)

def sign1(content_type, kid, payload):
    # COSE_Sign1, protected {1 alg EdDSA, 3 content type, 4 kid}, empty unprotected, no AAD.
    protected = cbor({1: -8, 3: content_type, 4: kid})
    signature = OPERATIONS.sign(cbor(["Signature1", protected, b"", payload]))
    return cbor([protected, {}, payload, signature])

RUN = "permguard.stream.run.v1"
RUN_DIGEST = b"permguard.stream.run.v1\n"
DECISION_RECORD = b"permguard.decision.v1\n"
KID = b"host.operations:vector"
PRODUCER = bytes.fromhex("01a3185c50007111a111111111111111")
BOOT = bytes.fromhex("01a3185c50007222b222222222222222")
RUN_ID = bytes([0x31] * 16)
SUCCESSOR_ID = bytes([0x32] * 16)
RESOURCE = "plane/data/zone/zone-a/ledger/ledger-1"
MEMBERSHIP = bytes.fromhex("01a3185c50007333c333333333333333")

def sha(domain, data): return hashlib.sha256(domain + data).digest()

records = [b'{"n":1}', b'{"n":2}']
last_digest = sha(DECISION_RECORD, records[-1])
fence = {1: MEMBERSHIP, 2: "decisions", 3: 4}
genesis = cbor({1: "data", 2: "decisions", 3: 1, 4: RESOURCE, 5: PRODUCER, 6: RUN_ID, 7: BOOT,
                8: 1_800_000_000, 10: fence})
end = {1: RUN_ID, 2: 2, 3: last_digest}
approval = bytes([0x55] * 32)
successor = cbor({1: "data", 2: "decisions", 3: 1, 4: RESOURCE, 5: PRODUCER, 6: SUCCESSOR_ID,
                  7: BOOT, 8: 1_800_000_100, 9: end, 11: approval})
genesis_envelope = sign1(RUN, KID, genesis)
successor_envelope = sign1(RUN, KID, successor)
group = cbor({1: 1, 2: records})
state = cbor({1: RUN_ID, 2: sha(RUN_DIGEST, genesis_envelope), 3: 3, 4: 2, 5: 1, 6: 1, 7: 1})
state_pending = cbor({1: RUN_ID, 2: sha(RUN_DIGEST, genesis_envelope), 3: 3, 4: 2, 5: 0, 6: 0,
                      7: 1, 8: successor_envelope, 9: 2})

out = {"comment": "Stream engine records (WP-5.1); see README.md and stream.py",
       "operations_public": OPERATIONS_PUB.hex(), "kid": KID.decode(),
       "producer_host_id": PRODUCER.hex(), "producer_boot_id": BOOT.hex(), "resource": RESOURCE,
       "membership_id": MEMBERSHIP.hex(),
       "genesis": {"run_id": RUN_ID.hex(), "payload": genesis.hex(),
                   "cose_sign1": genesis_envelope.hex(),
                   "digest": sha(RUN_DIGEST, genesis_envelope).hex()},
       "successor": {"run_id": SUCCESSOR_ID.hex(), "payload": successor.hex(),
                     "cose_sign1": successor_envelope.hex(), "approval": approval.hex()},
       "run_end": cbor(end).hex(),
       "records": [record.decode() for record in records],
       "last_record_digest": last_digest.hex(),
       "group": group.hex(),
       "state": state.hex(), "state_pending": state_pending.hex()}

json.dump(out, sys.stdout, indent=2, ensure_ascii=False)
sys.stdout.write("\n")
